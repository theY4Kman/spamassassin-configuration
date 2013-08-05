<?php

// Spamassassin Configuration Line Type
class SAType {
    const INVALID = -1;
    const UNKNOWN = 0;
    const WHITELIST_FROM = 1;
    const BLACKLIST_FROM = 2;
    const WHITELIST_FROM_RCVD = 3;

    private static $name_types = array(
        'whitelist_from' => self::WHITELIST_FROM,
        'whitelist_from_rcvd' => self::WHITELIST_FROM_RCVD,
        'blacklist_from' => self::BLACKLIST_FROM,
    );

    public static function get_type($name) {
        $key = strtolower($name);
        if (isset(self::$name_types[$key]))
            return self::$name_types[$key];
        else
            return self::UNKNOWN;
    }
}


class SpamassassinConfigurationLine {
    public $raw;
    public $rule;
    public $args;
    public $comment;
    public $type;

    /**
     * @param $raw string   The line before processing
     * @param $rule string  The first token of the line
     * @param $args string  The rest of the line before the comment
     * @param $comment string The comment (including the #) till the EOL
     */
    public function __construct($raw, $rule, $args, $comment) {
        $this->raw = $raw;
        $this->set_rule($rule);
        $this->args = $args;
        $this->comment = $comment;
        $this->deleted = false;
    }

    public function render() {
        if (!$this->rule)
            // ?: is shorthand for TEST ? TEST : DEFAULT
        return $this->comment ?: '';

        $line = $this->rule . ($this->args ? ' ' . $this->args : '');
        if ($this->comment)
            $line .= ' ' . $this->comment;

        return $line;
    }

    public function get_key() {
        // I wish this was smaller, but it should
        return md5($this->raw);
    }

    public function set_rule($rule) {
        $this->rule = $rule;
        $this->type = SAType::get_type($this->rule);
    }

    public function delete() {
        $this->deleted = true;
    }
}

/**
 * Parses Spamassassin configuration files (.cf), allows for manipulation, and
 * outputs valid files. Can also save comments and (some) whitespace.
 */
class SpamassassinConfiguration {
    private $whitelisted;
    private $blacklisted;
    private $lines;
    private $keyed;

    public function __construct($config, $save_comments=true, $save_whitespace=true) {
        $this->whitelisted = array();
        $this->last_whitelisted = null;
        $this->blacklisted = array();
        $this->last_blacklisted = null;

        $this->save_comments = $save_comments;
        $this->save_whitespace = $save_whitespace;

        $this->parse($config);
    }

    public static function from_file($path) {
        return new SpamassassinConfiguration(file_get_contents($path));
    }

    private function parse($input) {
        $lines = explode("\n", $input);
        $line_idx = 0;
        foreach ($lines as $line) {
            $cf_line = $this->parse_line($line);
            if ($cf_line === null)
                continue;

            $key = $cf_line->get_key();
            $this->keyed[$key] = $cf_line;
            $this->lines[] = $cf_line;

            switch ($cf_line->type) {
                case SAType::WHITELIST_FROM:
                case SAType::WHITELIST_FROM_RCVD:
                    $this->whitelisted[] = $cf_line;
                    $this->last_whitelisted = $line_idx;
                    break;

                case SAType::BLACKLIST_FROM:
                    $this->blacklisted[] = $cf_line;
                    $this->last_blacklisted = $line_idx;
                    break;
            }

            $line_idx++;
        }
    }

    private function parse_line($raw) {
        $comment = null;
        $rule = null;
        $args = null;

        $line = trim($raw);
        if (!$this->save_whitespace)
            return null;

        // Pull out the comment (if any)
        $index = 0;
        while (($index = strpos($line, '#', $index)) !== FALSE) {
            if ($index > 0 && $line[$index - 1] === '\\') {
                $index++;
                continue;
            }

            if ($this->save_comments)
                $comment = substr($line, $index);
            $line = substr($line, 0, $index);
            break;
        }

        $split = preg_split('/\s+/', $line, 2);
        $len = count($split);

        if ($len > 0) {
            $rule = $split[0];
            if ($len > 1)
                $args = $split[1];
        }

        return new SpamassassinConfigurationLine($raw, $rule, $args, $comment);
    }

    public function get_config() {
        $out = array();
        foreach ($this->lines as $cf_line)
            if (!$cf_line->deleted)
                $out[] = $cf_line->render();
        return implode("\n", $out);
    }

    private function get_line($key) {
        if (isset($this->keyed[$key]))
            return $this->keyed[$key];
        else
            return null;
    }

    private function add_line($cf_line, $index=-1) {
        if ($index === -1 || $index >= count($this->lines))
            $this->lines[] = $cf_line;
        else
            array_splice($this->lines, $index, 0, array($cf_line));
    }

    /**
     * @param $pattern string The email pattern to blacklist
     * @param null $line_key string The line's key as returned by
     *      get_blacklisted. This is used to edit a line (if possible), instead
     *      of adding a new one.
     * @return string The key of the line
     */
    public function add_blacklisted($pattern, $line_key=null) {
        if (($cf_line = $this->get_line($line_key)) === null) {
            $cf_line = $this->parse_line('blacklist_from ' . $pattern);
            $this->add_line($cf_line, $this->last_blacklisted !== null ? ++$this->last_blacklisted : -1);
            $this->blacklisted[] = $cf_line;
        } else {
            // Should really remove old lines from $keyed. Doesn't really
            // matter in my use case, though.
            $cf_line->args = $pattern;
        }

        $key = $cf_line->get_key();
        $this->keyed[$key] = $cf_line;
        return $key;
    }

    public function get_blacklisted() {
        $blacklisted = array();
        foreach ($this->blacklisted as $cf_line)
            if (!$cf_line->deleted)
                $blacklisted[] = array($cf_line->get_key(), $cf_line->args);
        return $blacklisted;
    }

    public function add_whitelisted($pattern, $rdns=null, $line_key=null) {
        $rule = $rdns ? 'whitelist_from_rcvd' : 'whitelist_from';
        $args = $pattern . ($rdns ? ' ' . $rdns : '');
        if (($cf_line = $this->get_line($line_key)) === null) {
            $cf_line = $this->parse_line($rule . ' ' . $args);
            $this->add_line($cf_line, $this->last_whitelisted !== null ? ++$this->last_whitelisted : -1);
            $this->whitelisted[] = $cf_line;
        } else {
            $cf_line->set_rule($rule);
            // Should really remove old lines from $keyed. Doesn't really
            // matter in my use case, though.
            $cf_line->args = $args;
        }

        $key = $cf_line->get_key();
        $this->keyed[$key] = $cf_line;
        return $key;
    }

    public function get_whitelisted() {
        $whitelisted = array();
        foreach ($this->whitelisted as $cf_line)
            if (!$cf_line->deleted)
                $whitelisted[] = array($cf_line->get_key(), $cf_line->args);
        return $whitelisted;
    }

    public function remove_line($key) {
        $this->keyed[$key]->delete();
    }
}
