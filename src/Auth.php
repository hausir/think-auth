<?php

namespace hausir;

use think\Config;

class Auth
{
    protected $config = [
        'user_model' => 'app\common\model\User',
        'token_model' => 'app\common\model\Token',
        'account_fields' => ['email', 'phone'],
    ];
    protected static $objUser;
    protected static $objToken;

    public function __construct($config = [])
    {
        $config = empty($config) ? Config::get('auth') : $config;
        $this->config = array_merge($this->config, $config);

        if (empty(static::$objUser)) {
            static::$objUser = new $this->config['user_model'];
        }

        if (empty(static::$objToken)) {
            static::$objToken = new $this->config['token_model'];
        }
    }

    /**
     * 验证账号密码登录
     * @return bool|object 成功返回user对象 失败返回false
     */
    public function login()
    {
        ['account' => $account, 'password' => $password] = $this->getBasic();
        $user = static::$objUser->getByAccount($account);
        if (empty($user) || !$user->verifyPassword($password)) {
            return false;
        }
        return static::$objToken->generate($user);
    }

    /**
     * 删除token退出登录
     * @return bool
     */
    public function logout()
    {
        $token = $this->getBare();
        return static::$objToken->deleteByToken($token);
    }

    /**
     * 根据token获取用户信息
     * @return object user对象
     */
    public function getInfo()
    {
        $token = $this->getBare();
        return static::$objUser->getByToken($token);
    }

    /**
     * 解析autorization http消息头
     * @return array|bool
     */
    protected function parse()
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

    /**
     * 获取对应的autho内容
     * @param  string $type
     * @return bool|mixed
     */
    protected function get($type)
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
    protected function getBasic()
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
    protected function getBare()
    {
        return static::get('Bare');
    }
}
