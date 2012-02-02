<?php
/**
 * SAE图像处理服务
 *
 * @author lijun
 * @version $Id$
 * @package sae
 *
 */

/**
 * SAE图像处理class
 * 可对2M以下大小的图像进行处理
 *
 * <code>
 * <?php
 * $f = new SaeFetchurl();
 * $img_data = $f->fetch( 'http://ss7.sinaimg.cn/bmiddle/488efcbbt7b5c4ae51ca6&690' );
 * $img = new SaeImage();
 * $img->setData( $img_data );
 * $img->resize(200); // 等比缩放到200宽
 * $img->flipH(); // 水平翻转
 * $img->flipV(); // 垂直翻转
 * $new_data = $img->exec(); // 执行处理并返回处理后的二进制数据
 * // 或者可以直接输出
 * $img->exec( 'jpg' , true );
 * 
 * //图片处理失败时输出错误码和错误信息
 * if ($new_data === false)
 *         var_dump($img->errno(), $img->errmsg());
 * ?>
 * </code>
 *
 * 错误码参考：
 *  - errno: 0         成功
 *  - errno: 3         参数错误
 *  - errno: 500     服务内部错误
 *  - errno: 999     未知错误
 *  - errno: 403     权限不足或超出配额
 *
 * @package sae
 * @author  lijun
 * 
 */
class SaeImage extends SaeObject 
{
    private $_accesskey = "";
    private $_secretkey = "";
    private $_errno=SAE_Success;
    private $_errmsg="OK";
    private $_img_data;
    private $_height = 0;
    private $_width = 0;
    private $_post = array();
    private $_format;

    /**
     * @ignore
     */
    const baseimgurl = "http://image.sae.sina.com.cn/index.php";
    /**
     * @ignore
     */
    const image_limitsize = 2097152;

    /**
     * 构造SaeImage对象
     *
     * @param mixed $img_data img_data参数可以为二进制图片数据，也可以是用于composite图片合成的数组，数组格式:
     * <pre>
     *              array(array('blob1',x1,y1,opacity1,anchor1),
     *                array('blob2',x2,y2,opacity2,anchor2),
     *                array('blob3',x3,y3,opacity3,anchor3)
     *                      );
     * </pre>
     * 当合并（composite）图片时，$img_data必须设定
     */
    function __construct($img_data="") {

        $this->_accesskey = SAE_ACCESSKEY;
        $this->_secretkey = SAE_SECRETKEY;

        return $this->setData($img_data);
    }

    /**
     * 返回错误信息
     *
     * @return string
     * @author Lijun
     */
    public function errmsg() {
        return $this->_errmsg;
    }

    /**
     * 返回错误编号
     *
     * @return int
     * @author Lijun
     */
    public function errno() {
        return $this->_errno;
    }

    /**
     * 取得图像属性
     *
     * @return array 错误时返回false
     * @author Lijun
     */ 
    public function getImageAttr() {
        if($this->imageNull()) return false;
        $fn = tempnam(SAE_TMP_PATH, "SAE_IMAGE");
        if ($fn == false) {
            $this->_errmsg = "tempnam call failed when getImageAttr";
            return false;
        }
        if(!file_put_contents($fn, $this->_img_data)) {
            $this->_errmsg = "file_put_contents to SAETMP_PATH failed when getImageAttr";
            return false;
        }
        if(!($size = getimagesize($fn, $info))) {
            $this->_errmsg = "getimagesize failed when getImageAttr";
            return false;
        }
        foreach($info as $k=>$v) {
            $size[$k] = $v;
        }
        $this->_width = $size[0];
        $this->_height = $size[1];
        return $size;
    }

    /**
     * 将对象的数据重新初始化,用于多次重用一个SaeImgae对象
     *
     * <code>
     * <?php
     * $img = new SaeImage( $bin );
     * $img->resize(100);
     * $data1 = $img->exec();
     * $img->clean();
     * $img->setData( $bin2 );
     * $img->resize(300);
     * $data2 = $img->exec();
     * ?>
     * </code>
     *
     * @return void
     * @author Lijun
     */
    public function clean()
    {
        $this->_post = array();
        $this->_img_data = NULL;
    }

    /**
     * 设置key.
     *
     * 只有使用其他应用的key时才需要调用
     *
     * @param string $accesskey 
     * @param string $secretkey 
     * @return bool
     * @author Lijun
     */
    public function setAuth( $accesskey, $secretkey) {
        $accesskey = trim($accesskey);
        $secretkey = trim($secretkey);

        $this->_accesskey = $accesskey;
        $this->_secretkey = $secretkey;
        return true;
    }

    /**
     * 设置要处理的图片二进制数据或数组，格式同构造函数的img_data参数
     *
     * @param string $img_data 
     * @return bool
     * @author Lijun
     */
    public function setData( $img_data ) {
        if(is_array($img_data)) {
            $_size = 0;
            foreach($img_data as $k => $i) {
                if(count($i) < 1 || count($i) > 5) {
                    $this->_errno = SAE_ErrParameter;
                    $this->_errmsg = "image data array you supplied invalid";
                    return false;
                }
                if (is_null($i[1]) || $i[1] === false ) $img_data[$k][1] = 0;
                if (is_null($i[2]) || $i[1] === false ) $img_data[$k][2] = 0;
                if (is_null($i[3]) || $i[1] === false ) $img_data[$k][3] = 1;
                if (is_null($i[4]) || $i[1] === false ) $img_data[$k][4] = SAE_TOP_LEFT;
                $_size += strlen($i[0]);
            }
            if($_size > self::image_limitsize) {
                $this->_errno = SAE_ErrParameter;
                $this->_errmsg = "image datas length more than 2M";
                return false;
            }
        } else if(strlen($img_data) > self::image_limitsize) { 
            $this->_errno = SAE_ErrParameter;
            $this->_errmsg = "image data length more than 2M";
            return false;
        }
        $this->_img_data = $img_data;

        return true;
    }

    /**
     * 缩放图片,只指定width或者height时,将进行等比缩放
     *
     * @param int $width 
     * @param int $height 
     * @return bool
     * @author Lijun
     */
    public function resize($width=0, $height=0) {
        $width = intval($width);
        $height = intval($height);
        if($this->imageNull()) return false;
        array_push($this->_post, array("act"=>"resize", "width"=>$width, "height"=>$height));
        return true;
    }

    /**
     * 按比例缩放.1为原大小
     *
     * @param float $ratio 
     * @return bool
     * @author Lijun
     */
    public function resizeRatio($ratio=0.5) {
        $ratio = floatval($ratio);
        if($this->imageNull()) return false;
        if($this->_width == 0) {
            $attr = $this->getImageAttr();
            if(! $attr) return false;
        }
        array_push($this->_post, array("act"=>"resize", "width"=>$this->_width*$ratio, "height"=>$this->_height*$ratio));
        return true;
    }

    /**
     * 对图片进行裁剪
     *
     * @param float $lx x起点(百分比模式,1为原图大小,如0.25) 
     * @param float $rx x终点(百分比模式,1为原图大小,如0.75) 
     * @param float $by y起点(百分比模式,1为原图大小,如0.25) 
     * @param float $ty y终点(百分比模式,1为原图大小,如0.75) 
     * @return bool
     * @author Lijun
     */
    public function crop($lx=0.25, $rx=0.75, $by=0.25, $ty=0.75) {
        $lx = floatval($lx);
        $rx = floatval($rx);
        $by = floatval($by);
        $ty = floatval($ty);
        if($this->imageNull()) return false;
        array_push($this->_post, array("act"=>"crop", "lx"=>$lx, "rx"=>$rx, "by"=>$by, "ty"=>$ty));
        return true;
    }

    /**
     * 顺时针旋转图片
     *
     * @param int $degree 旋转度数（0 - 360）
     * @return bool
     * @author Lijun
     */
    public function rotate($degree=90) {
        $degree = intval($degree);
        if($this->imageNull()) return false;
        array_push($this->_post, array("act"=>"rotate", "degree"=>$degree));
        return true;
    }

    /**
     * 水平翻转
     *
     * @return bool
     * @author Lijun
     */
    public function flipH() {
        if($this->imageNull()) return false;
        array_push($this->_post, array("act"=>"flipH"));
        return true;
    }

    /**
     * 垂直翻转
     *
     * @return bool
     * @author Lijun
     */
    public function flipV() {
        if($this->imageNull()) return false;
        array_push($this->_post, array("act"=>"flipV"));
        return true;
    }

    /**
     * 添加文字注解，可用于文字水印
     *
     * @param string $txt 必须为utf8编码
     * @param float $opacity 设置不透明度
     * @param constant $gravity 设置文字摆放位置, SAE_NorthWest,SAE_North,SAE_NorthEast,SAE_West,
     *                SAE_Center,SAE_East,SAE_SouthWest,SAE_South,SAE_SouthEast,SAE_Static
     * @param array $font 字体数组可以设置如下属性:
     * <pre>
     *    name,常量,字体名称，如果需要添加中文注解，请使用中文字体，否则中文会显示乱码。
     *      支持的字体：SAE_SimSun(宋体,默认)、SAE_SimKai(楷体)、SAE_SinHei(正黑)、SAE_Arial
     *    weight,字体宽度,int
     *    size，字体大小,int
     *    color,字体颜色,例如："blue", "#0000ff", "rgb(0,0,255)"等，默认为"black";
     * </pre>
     *
     * @return bool
     * @author Lijun
     */
    public function annotate($txt, $opacity=0.5, $gravity=SAE_Static,
        $font = array("name"=>SAE_SimSun, "size"=>15, "weight"=>300, "color"=>"black")) {
            $opacity = floatval($opacity);
            if($this->imageNull()) return false;

            array_push($this->_post, array("act"=>"annotate", "txt"=>$txt, "opacity"=>$opacity,
                "gravity"=>$gravity, "font"=>array("name"=>$font['name'],"size"=>$font["size"],
                "weight"=>$font["weight"],"color"=>$font["color"])));

            return true;
        }

    /**
     * 去噪点,改善图片质量，通常用于exec之前
     *
     * @return bool
     * @author Lijun
     */
    public function improve() {
        if($this->imageNull()) return false;
        array_push($this->_post, array("act"=>"improve"));
        return true;
    }

    /**
     * 进行图片处理操作
     *
     * @param string $format 图片格式,支持gif,jpg和png
     * @param bool $display 是否直接输出，false:不输出，true:输出，默认false
     * @return mixed 若设置$display为true，返回void，否则返回图片二进制数据
     * @author Lijun
     */
    public function exec($format="jpg", $display=false) {
        if($this->imageNull()) return false;
        if(!in_array($format, array('jpg', 'gif', 'png'))) {
            $this->_errno = SAE_ErrParameter;
            $this->_errmsg = "format must be one of 'jpg', 'gif' and 'png'";
            return false;
        } else {
            $this->_format = $format;
        }
        if($this->_post[0]["act"] == "composite" && is_array($this->_img_data)) {
            foreach($this->_img_data as $k=>$v) {
                $this->_img_data[$k][0] = base64_encode($v[0]); //unset($v[0]);
            }
            array_unshift($this->_post, array("format"=>$format, "imagedata"=>$this->_img_data));
        } else {
            array_unshift($this->_post, array("format"=>$format, "imagedata"=>base64_encode($this->_img_data)));
        }

        if($this->_post[1]["act"] == "composite" && !is_array($this->_post[0]["imagedata"])) {
            $this->_errno = SAE_ErrParameter;
            $this->_errmsg = "composite imagedata must be an array, pls see doc:";
            return false;
        }
        if($this->_post[1]["act"] != "composite" && is_array($this->_post[0]["imagedata"])) {
            $this->_errno = SAE_ErrParameter;
            $this->_errmsg = "imagedata is array only when composite image and composite must be the first operation";
            return false;
        }

        foreach($this->_post as $k=>$a) {
            if(isset($a["act"]) && $a["act"] == 'composite' && $k != 1) {
                $this->_errno = SAE_ErrParameter;
                $this->_errmsg = "composite operation must be the first operation!";
                return false;
            }
        }
        $tobepost = json_encode($this->_post);
        $ret = $this->postImgData(array("saeimg"=>$tobepost));
        if($ret && $display) {
            header("Content-Type: image/$format");
            echo $ret;
            return true;
        } else {
            return $ret;
        }
    }

    /**
     * 图片合成，可以进行多张图片的合成，也可以做图片水印用
     * <pre>
     * 注意composite方法在和其它图片处理方法一起使用时，composite必须第一个被调用
     * 在图片合成时，初始化对象传递imageData数据需要是一个二维数组。
     * </pre>
     * 数组中的每个成员也是数组，需要包含5个元素：
     * - 表示图像数据的blob字符串 (blob string)
     * - 表示在画布上放置图像时相对锚点位置的 x 偏移的像素数（可能为负）
     * - 表示在画布上放置图像时相对锚点位置的 y 偏移的像素数（可能为负）
     * - 表示图像不透明度(opacity)的浮点数，在 0.0 至 1.0 之间（包括 0.0 和 1.0）0表示全透明，1表示最不透明。
     * - 画布上锚点的位置，是以下之一：
     * <pre>
     *     SAE_TOP_LEFT SAE_TOP_CENTER SAE_TOP_RIGHT SAE_CENTER_LEFT SAE_CENTER_CENTER 
     *     SAE_CENTER_RIGHT SAE_BOTTOM_LEFT SAE_BOTTOM_CENTER SAE_BOTTOM_RIGHT
     * </pre>
     * 注意上面的x偏移和y偏移，和锚点位置有关，如果选择了锚点TOP_RIGHT,<br>
     * 则x和y的偏移是指该图片的TOP_RIGHT(右上角)相对于画布的右上角的偏移；<br>
     * 但如果选择BOTTOM_LEFT(左下角)为锚点，则x/y偏移就是指该图片的左下角<br>
     * 相对于画布的左下角的偏移量。<br>
     * <b>偏移的正负同数学中的象限规定。</b><br>
     * 图片的放置顺序同数组中出现的顺序
     *
     * <code>
     * <?php
     * //从网络上抓取要合成的多张图片
     * $img1 = file_get_contents('http://ss2.sinaimg.cn/bmiddle/53b05ae9t73817f6bf751&690');
     * $img2 = file_get_contents('http://timg.sjs.sinajs.cn/miniblog2style/images/common/logo.png');
     * $img3 = file_get_contents('http://i1.sinaimg.cn/home/deco/2009/0330/logo_home.gif');
     * 
     * //实例化SaeImage并取得最大一张图片的大小，稍后用于设定合成后图片的画布大小
     * $img = new SaeImage( $img1 );
     * $size = $img->getImageAttr();
     * 
     * //清空$img数据
     * $img->clean();
     * 
     * //设定要用于合成的三张图片（如果重叠，排在后面的图片会盖住排在前面的图片）
     * $img->setData( array(
     * array( $img1, 0, 0, 1, SAE_TOP_LEFT ),
     * array( $img2, 0, 0, 0.5, SAE_BOTTOM_RIGHT ),
     * array( $img3, 0, 0, 1, SAE_BOTTOM_LEFT ),
     * ) );
     * 
     * //执行合成
     * $img->composite($size[0], $size[1]);
     * 
     * //输出图片
     * $img->exec('jpg', true);
     * ?>
     * </code>
     * @param int $width 设置画布宽度
     * @param int $height 设置画布高度
     * @param string $color 设置画布颜色
     * @return bool
     * @author Lijun
     */
    public function composite($width, $height, $color="black") {
        $width = intval($width);
        $height = intval($height);
        if($this->imageNull()) return false;
        array_push($this->_post, array("act"=>"composite", "width"=>$width, "height"=>$height, "color"=>$color));
        return true;
    }

    private function postImgData($post) {
        $url = self::baseimgurl;
        $s = curl_init();
        curl_setopt($s,CURLOPT_URL,$url);
        curl_setopt($s,CURLOPT_HTTP_VERSION,CURL_HTTP_VERSION_1_0);
        curl_setopt($s,CURLOPT_TIMEOUT,15);
        curl_setopt($s,CURLOPT_RETURNTRANSFER,true);
        curl_setopt($s,CURLOPT_HEADER, 1);
        curl_setopt($s,CURLINFO_HEADER_OUT, true);
        curl_setopt($s,CURLOPT_HTTPHEADER, $this->genReqestHeader($post));
        curl_setopt($s,CURLOPT_POST,true);
        curl_setopt($s,CURLOPT_POSTFIELDS,$post); 
        $ret = curl_exec($s);
        // exception handle, if error happens, set errno/errmsg, and return false
        $info = curl_getinfo($s);

        if(empty($info['http_code'])) {
            $this->_errno = SAE_ErrInternal;
            $this->_errmsg = "image service segment fault";
            return false;
        } else if($info['http_code'] != 200) {
            $this->_errno = SAE_ErrInternal;
            $this->_errmsg = "image service internal error";
            return false;
        } else {
            if($info['size_download'] == 0) { // get ImageError header
                $header = substr($ret, 0, $info['header_size']);
                $imageheader = $this->extractCustomHeader("ImageError", $header);
                if($imageheader == false) { // not found ImageError header
                    $this->_errno = SAE_ErrUnknown;
                    $this->_errmsg = "unknown error";
                    return false;
                }
                $err = explode(",", $imageheader, 2);
                $this->_errno = $err[0];
                $this->_errmsg = $err[1];
                return false;
            } else {
                $body = substr($ret, -$info['size_download']);
                return $body;
            }
        }
        return $ret;
    }

    private function genSignature($content, $secretkey) {
        $sig = base64_encode(hash_hmac('sha256',$content,$secretkey,true));
        return $sig;
    }

    private function genReqestHeader($post) {
        $timestamp = date('Y-m-d H:i:s');
        $cont1 = "ACCESSKEY".$this->_accesskey."TIMESTAMP".$timestamp;
        $reqhead = array("TimeStamp: $timestamp","AccessKey: ".$this->_accesskey, "Signature: " . $this->genSignature($cont1, $this->_secretkey));
        return $reqhead;
    }

    private function extractCustomHeader($key, $header) {
        $pattern = '/'.$key.'(.*?)'."\n/";
        if (preg_match($pattern, $header, $result)) {
            return $result[1];
        } else {
            return false;
        }
    }

    private function imageNull() {
        if(is_array($this->_img_data) && count($this->_img_data) == 0) {
            $this->_errno = SAE_ErrParameter;
            $this->_errmsg = "image data cannot be empty";
            return true;
        }
        if(!is_array($this->_img_data) && $this->_img_data == "") {
            $this->_errno = SAE_ErrParameter;
            $this->_errmsg = "image data cannot be empty";
            return true;
        }
        return false;
    }
}

