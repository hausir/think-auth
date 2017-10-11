<?php

namespace hausir;

class Auth
{
    /** 解析autorization http消息头
     * @return array|bool
     */
    public static function parse()
    {
        if (function_exists('apache_request_headers')) {
            $header = apache_request_headers();
            $authorization = empty($header['Authorization']) ? '' : $header['Authorization'];
        } else {
            $authorization = empty($_SERVER['HTTP_AUTHORIZATION']) ? '' : $_SERVER['HTTP_AUTHORIZATION'];
        }
        if (empty($authorization)) {
            return false;
        }

        list($type, $value) = explode(' ', $authorization);

        if (empty($type) || empty($value)) {
            return false;
        }


        return [
            'type' => $type,
            'value' => $value
        ];

    }

    /**获取对应的autho内容
     * @param  string $type
     * @return bool|mixed
     */
    public static function get($type)
    {
        $auth = static::parse();
        if (empty($auth) || $auth['type'] !== $type) {
            return false;
        }
        return $auth['value'];

    }

    /**
     * 获取认证用户信息
     * @return bool|mixed
     */
    public static function getBasic()
    {
        $data = static::get('Basic');
        if (empty($data)) {
            return false;
        }
        list($account, $password) = explode(':', base64_decode($data));
        return [
            'account' => $account,
            'password' => $password
        ];
    }

    /**
     * 获取认证token
     * @return bool|mixed
     */
    public static function getBare()
    {
        return static::get('Bare');
    }
}
