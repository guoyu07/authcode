<?php
/**
 * Created by PhpStorm.
 * User: wuhua
 * Mail: wolferhua@hashmap.cn
 * Date: 2017-11-9
 * Time: 12:28
 */

class AuthCode
{

    private static $apps = [
        'wolferhua' => [
            //应用名称
            'name' => '',
            //应用编号
            'id' => '',
            // 应用key
            'key' => 'wolferhua',
            // 随机秘钥长度
            'len' => 4,
            // 随机秘钥长度
            'swap' => [
                'size' => 51,
                'point' => [
                    [1, 33],
                    [2, 8],
                    [3, 11],
                    [4, 15],
                    [5, 21],
                    [6, 25],
                    [9, 30],
                    [10, 42],
                    [18, 50],
                    [19, 51]
                ]
            ]
        ]
    ];

    /**
     * 数据打包
     * @param $data
     * @param string $app
     * @return string
     */
    public static function pack($data, $appId = '', $expire = 0)
    {
        //应用信息
        $app = self::appInfo($appId);
        $len = $app['len'] > 30 ? 30 : $app['len'];
        $key = $app['key'];
        $en_key = md5($key);
        $mixed_str = base64_encode(md5($key . microtime()));
        //源字符串
        $signSrcStr = self::base64_encode(self::serialize($data));
        $swapSrcStr = self::swap($signSrcStr, $app['swap']);

        $now = time();
        //时间
        $time_str = sprintf("%010d", $expire ? $expire + $now : '0');
        $now_str = sprintf("%010d", $now);

        //混合秘钥
        $mixed_sub = $len > 0 ? substr($mixed_str, 0, $len) : '';
        //数据，换位
        $dataStr = self::swap("{$mixed_sub}{$time_str}{$swapSrcStr}", $app['swap']);

        //签名 "当前时间-数据串-秘钥"
        $sign = md5("timestamp={$now_str}&data={$dataStr}&{$en_key}");
        $pack_data = [
            'data' => $dataStr,
            'sign' => $sign,
            'timestamp' => $now,
            'appId' => $appId
        ];

        //打包数据
        $pack = self::base64_encode(self::serialize($pack_data));
        //换位后返回
        return self::swap($pack);
    }

    /**
     * 应用信息
     * @param $id
     * @return array|mixed
     */
    public static function appInfo($id)
    {
        //todo 获取产品秘钥，目前写死，可以拓展这个方法
        if (isset(self::$apps[$id])) return self::$apps[$id];
        //默认信息
        return [
            //应用名称
            'name' => '',
            //应用编号
            'id' => '',
            // 应用key
            'key' => 'wolferhua',
            // 随机秘钥长度
            'len' => 4,
            'swap' => [],
        ];
    }

    /**
     * 数据 base 64
     * @param string $string
     * @return mixed
     */
    public static function base64_encode($string = '')
    {
        $code = \base64_encode($string);
        //由于标准的Base64编码后可能出现字符+和/，在URL中就不能直接作为参数，所以又有一种"url safe"的base64编码，其实就是把字符+和/分别变成-和_并去掉等号
        //因为Base64是把3个字节变为4个字节，所以，Base64编码的长度永远是4的倍数，因此，需要加上=把Base64字符串的长度变为4的倍数，就可以正常解码了。
        return str_replace([
            '+',
            '/',
            '='
        ], [
            '-',
            '_',
            ''
        ], $code);
    }

    /**
     * 序列化数据
     * @param $data
     * @return array|string
     */
    public static function serialize($data)
    {
        if (is_object($data) || is_array($data)) {
            return json_encode(self::ksort($data));
        }
        return $data;
    }

    /**
     * 数组排序
     * @param $data
     * @return array|bool
     */
    public static function ksort($data)
    {
        if (is_array($data)) {
            ksort($data);
        } elseif (is_object($data)) {
            $data = get_object_vars($data);
            ksort($data);
        }
        return $data;
    }

    /**
     * 字符串换位
     * @param string $string
     * @param array $swap
     * @return string
     */
    public static function swap($string = '', $swap = [])
    {
        $size = isset($swap['size']) ? intval($swap['size']) : 51;
        $points = isset($swap['point']) && is_array($swap['point']) && $swap['point'] ? $swap['point'] : [
            [1, 33],
            [2, 8],
            [3, 11],
            [4, 15],
            [5, 21],
            [6, 25],
            [9, 30],
            [10, 42],
            [18, 50],
            [19, 51]
        ];

        //判断换位满足条件
        if (is_string($string) && strlen($string) >= $size) {
            $bytes = self::strToBytes($string);
            foreach ($points as $point) {
                if (isset($point[0]) && isset($point[1])) {
                    if (isset($bytes[$point[0]]) && isset($bytes[$point[1]])) {
                        //执行换位
                        $temp = $bytes[$point[0]];
                        $bytes[$point[0]] = $bytes[$point[1]];
                        $bytes[$point[1]] = $temp;
                    }
                }
            }
            $string = self::byteToStr($bytes);
        }

        return $string;

    }

    /**
     * 字符串转换为字节数组
     * @param $string
     * @return array
     */
    private static function strToBytes($string)
    {
        //转化为数组
        $bytes = array();
        for ($i = 0; $i < strlen($string); $i++) {
            $bytes[] = $string[$i];
        }
        return $bytes;
    }

    /**
     * 字节转字符串
     */
    private static function byteToStr($bytes)
    {
        $str = '';
        foreach ($bytes as $ch) {
            $str .= $ch;
        }
        return $str;
    }

    /**
     * 从包里获取数据。
     * @param $pack
     * @return null
     */
    public static function getDataByPack($pack)
    {
        $packData = self::unpack($pack);
        if (isset($packData['data'])) {
            return $packData['data'];
        }
        return null;
    }

    /**
     * 数据解包
     * @param $pack
     * @return mixed|null
     */
    public static function unpack($pack)
    {
        //解包
        //先换位
        $swap_pack = self::swap($pack);
        //解除数据包
        $pack_ser = self::base64_decode($swap_pack);
        if (!$pack_ser) {
            return null;
        };
        $pack_data = self::unserialize($pack_ser);
        //获取到appId
        if (!$pack_data || !isset($pack_data['appId'])) {
            return null;
        }
        $app = self::appInfo($pack_data['appId']);
        $len = $app['len'] > 30 ? 30 : $app['len'];
        $key = $app['key'];
        $en_key = md5($key);

        //验签
        $pack_sign = isset($pack_data['sign']) ? $pack_data['sign'] : '';
        if (!$pack_sign) {
            return null;
        }
        $pack_data['data'] = isset($pack_data['data']) ? $pack_data['data'] : '';
        $pack_data['timestamp'] = isset($pack_data['timestamp']) ? intval($pack_data['timestamp']) : 0;
        $now_str = sprintf("%010d", $pack_data['timestamp']);
        $sign = md5("timestamp={$now_str}&data={$pack_data['data']}&{$en_key}");
        if ($sign != $pack_sign) {
            return null;
        }

        //数据解包

        //先换位
        $pack_data_swap = self::swap($pack_data['data'], $app['swap']);
        //取出混合秘钥
        if ($len > 0) {
            $pack_data_swap = substr($pack_data_swap, $len);
        }
        //取出时间过期时间
        $expire = substr($pack_data_swap, 0, 10);
        if ($expire > 0 && $expire < time()) {
            //过期
            return null;
        }

        //剩下绝对数据了
        $pack_data_swap = substr($pack_data_swap, 10);
        $data = self::unserialize(self::base64_decode(self::swap($pack_data_swap, $app['swap'])));
        $pack_data['data'] = $data;
        return $pack_data;
    }

    /**
     * base64 解密
     * @param string $code
     * @return bool|string
     */
    public static function base64_decode($code = '')
    {
        $real_code = str_replace([
            '-',
            '_'
        ], [
            '+',
            '/'
        ], $code);
        $len = strlen($real_code);
        //因为Base64是把3个字节变为4个字节，所以，Base64编码的长度永远是4的倍数，因此，需要加上=把Base64字符串的长度变为4的倍数，就可以正常解码了。
        $repair_len = $len % 4;
        if ($repair_len > 0) {
            $real_code .= str_repeat('=', 4 - $repair_len);
        }
//        var_dump($repair_len);
//        var_dump($code);


        return \base64_decode($real_code);
    }

    /**
     * 反序列化
     * @param $data
     * @return mixed
     */
    public static function unserialize($data)
    {
        $jsonData = json_decode($data, true);
        // 检测是否为JSON数据 true 返回JSON解析数组, false返回源数据
        return (null === $jsonData) ? $data : $jsonData;
    }
}