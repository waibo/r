<?php
// settings
define('SAE_FETCHURL_SERVICE_ADDRESS','http://fetchurl.sae.sina.com.cn');

// storage
define( 'SAE_STOREHOST', 'http://stor.sae.sina.com.cn/storageApi.php' );
define( 'SAE_S3HOST', 'http://s3.sae.sina.com.cn/s3Api.php' );

// saetmp constant
define( 'SAE_TMP_PATH' , $SAE_TMPFS_PATH);

if ( isset($_SERVER['HTTP_MYSQLPORT']) && $_SERVER['HTTP_MYSQLPORT'] > 0 ) {
    $_SERVER['HTTP_MYSQLPORT'] = 3307;
}

define( 'SAE_APPNAME', sae_get_env('AppName') );
define( 'SAE_APPVERSION', sae_get_env('AppVersion') );
define( 'SAE_ACCESSKEY', sae_get_env('AccessKey') );
define( 'SAE_SECRETKEY', sae_get_env('SecretKey') );
$_SERVER['HTTP_SECRETKEY'] = 'Discarded';

// document root
$_SERVER['DOCUMENT_ROOT'] = rtrim($_SERVER['DOCUMENT_ROOT'], "/");
$_SERVER['DOCUMENT_ROOT'] = $_SERVER['DOCUMENT_ROOT'] . "/" . sae_get_env('AppHash') . "/" . SAE_APPNAME . "/" . SAE_APPVERSION;

define( 'SAE_MYSQL_HOST_M', 'w.rdc.sae.sina.com.cn' );
define( 'SAE_MYSQL_HOST_S', 'r.rdc.sae.sina.com.cn' );
define( 'SAE_MYSQL_PORT', 3307 );
define( 'SAE_MYSQL_USER', SAE_ACCESSKEY );
define( 'SAE_MYSQL_PASS', SAE_SECRETKEY );
define( 'SAE_MYSQL_DB', 'app_' . SAE_APPNAME );

// gravity define
define("SAE_NorthWest", 1);
define("SAE_North", 2);
define("SAE_NorthEast",3);
define("SAE_East",6);
define("SAE_SouthEast",9);
define("SAE_South",8);
define("SAE_SouthWest",7);
define("SAE_West",4);
define("SAE_Static",10);
define("SAE_Center",5);

// font stretch
define("SAE_Undefined",0);
define("SAE_Normal",1);
define("SAE_UltraCondensed",2);
define("SAE_ExtraCondensed",3);
define("SAE_Condensed",4);
define("SAE_SemiCondensed",5);
define("SAE_SemiExpanded",6);
define("SAE_Expanded",7);
define("SAE_ExtraExpanded",8);
define("SAE_UltraExpanded",9);

// font style
define("SAE_Italic",2);
define("SAE_Oblique",3);

// font name
define("SAE_SimSun",1);
define("SAE_SimKai",2);
define("SAE_SimHei",3);
define("SAE_Arial",4);
define("SAE_MicroHei",5);

// anchor postion
define("SAE_TOP_LEFT","tl");
define("SAE_TOP_CENTER","tc");
define("SAE_TOP_RIGHT","tr");
define("SAE_CENTER_LEFT","cl");
define("SAE_CENTER_CENTER","cc");
define("SAE_CENTER_RIGHT","cr");
define("SAE_BOTTOM_LEFT","bl");
define("SAE_BOTTOM_CENTER","bc");
define("SAE_BOTTOM_RIGHT","br");

// errno define
define("SAE_Success", 0); // OK
define("SAE_ErrKey", 1); // invalid accesskey or secretkey
define("SAE_ErrForbidden", 2); // access fibidden for quota limit
define("SAE_ErrParameter", 3); // parameter not exist or invalid
define("SAE_ErrInternal", 500); // internal Error
define("SAE_ErrUnknown", 999); // unknown error

// fonts for gd
define("SAE_Font_Sun", "/usr/share/fonts/chinese/TrueType/uming.ttf");
define("SAE_Font_Kai", "/usr/share/fonts/chinese/TrueType/ukai.ttf");
define("SAE_Font_Hei", "/usr/share/fonts/chinese/TrueType/wqy-zenhei.ttc");
define("SAE_Font_MicroHei", "/usr/share/fonts/chinese/TrueType/wqy-microhei.ttc");


/**
 * SaeObject
 *
 * @package sae
 * @ignore
 */
abstract class SaeObject implements SaeInterface
{
    function __construct()
    {
        // 
    }
}

/**
 * SaeInterface , public interface of all sae client apis
 *
 * all sae client classes must implement these method for setting accesskey and secretkey , getting error infomation.
 * @package sae
 * @ignore
 **/
interface SaeInterface
{
    public function errmsg();
    public function errno();
}


function is_https() {
    return ( ( isset($_SERVER['HTTP_APPMASK']) && $_SERVER['HTTP_APPMASK'] & 0x1 ) || ( isset($_SERVER['HTTP_X_PROTO']) && $_SERVER['HTTP_X_PROTO'] == 'SSL' ) );
}
if ( is_https() ) {
    $_SERVER['HTTPS'] = 'on';
}

function saeAutoLoader( $class_name )
{
    $file = dirname( __FILE__ ) . '/' . strtolower($class_name) . '.class.php';
    if( file_exists($file) )
        include_once( $file );
    if(!class_exists($class_name) && function_exists('__autoload'))
        __autoload($class_name);
    if(!class_exists($class_name) && function_exists('__sae_autoload'))
        __sae_autoload($class_name);
}

spl_autoload_register('saeAutoLoader');

function sae_xhprof_start()
{
     xhprof_enable(XHPROF_FLAGS_CPU + XHPROF_FLAGS_MEMORY);
}

function sae_xhprof_end()
{
    $data = xhprof_disable();
    if ( !empty($data) ) {
        $s = new SaeStorage();
        $s->write( 'xhprof' , 'xhprof_data_' . time() , serialize( $data ) );
    }
    return $data;
}

if (!function_exists('fsockopen')) {
    function fsockopen($hostname, $port = 80, &$errno = null, &$errstr = null, $timeout = 5) {

        srand(time() + crc32($hostname));

        $fp = FALSE;
        for ($i = 0; $i < 5 && !$fp; $i++) {
            $index = rand();    
            $fp = fsockopen_($index, 8000, $errno, $errstr, 5);
        }

        if ($fp) {
            $accesskey = SAE_ACCESSKEY;
            $secretkey = SAE_SECRETKEY;
            $endpoint  = "$hostname:$port";
            $signature = base64_encode(hash_hmac('sha256', $endpoint, $secretkey, true));

            $request = "$accesskey $signature $endpoint $timeout\r\n";

            fwrite($fp, $request);
            $response = fread($fp, 128);
            if ($response !== FALSE) {
                rtrim($response, "\r\n");
                list($errno, $errstr) = explode(":", $response, 2);
                if ($errno != 0) {
                    fclose($fp);    
                    $fp = FALSE;
                }
            } else {
                fclose($fp);
                $fp = FALSE;
                $errno = 500;
                $errstr = "Internal Error In Handshake";
            }
        }

        return $fp;
    }
}

//function sae_debug($errmsg)
//{
//    return trigger_error($errmsg, E_USER_WARNING);
//}

// =====================================================
// 以下函数全部为对0.1版本向前兼容用,不再推荐使用
// easychen@gmail.com
// =====================================================



// image
function sae_image_init( $ak='', $sk='', $image_bin = '' )
{
    if( !isset( $GLOBALS['sae_image_instance'] ) )
    {
        include_once( 'sae_image.class.php' );
        $GLOBALS['sae_image_instance'] = new sae_image( $ak, $sk, $image_bin );
    }

    return $GLOBALS['sae_image_instance'];

}




// storage
function sae_storage_init( $accesskey ,  $secretkey , $ssl = false )
{
    if( !isset( $GLOBALS['sae_storage_instance'] ) )
    {
        include_once( 'sae_storage.class.php' );
        $GLOBALS['sae_storage_instance'] = new sae_storage( $accesskey ,  $secretkey , $ssl );
    }

    return $GLOBALS['sae_storage_instance'];
}



// mysql
function sae_mysql_init( $host , $port , $accesskey , $secretkey , $appname , $do_replication = true )
{
    if( !isset( $GLOBALS['sae_mysql_instance'] ) )
    {
        include_once( 'sae_mysql.class.php' );
        $GLOBALS['sae_mysql_instance'] = new sae_mysql( $host , $port , $accesskey , $secretkey , $appname , $do_replication );
    }

    return $GLOBALS['sae_mysql_instance'];
}

// fetch url
//-------------------------------------------------------------------------------------------------

function _header_info($header)
{
 $hinfo = array();
 $header_lines = explode("\r",trim( $header));
 $first = array_shift($header_lines);
 // HTTP/1.1 301 Moved Permanently
 $reg ="/HTTP\/(.+?)\s([0-9]+)\s(.+)/is";
 if(preg_match($reg,trim($first),$out))
   {
    $hinfo['version'] = $out[1];
    $hinfo['code'] = $out[2];
    $hinfo['code_info'] = $out[3];
   }
 else
    return false;
 if(is_array($header_lines))
   {
    foreach($header_lines as $line)
           {
            $fs=explode( ":" , trim($line),2);
            if(strlen(trim($fs[0])) > 0 )
              {
               if(isset( $hinfo[strtolower(trim($fs[0]))] ) )
                  $hinfo[strtolower(trim($fs[0]))] = array_merge( (array)$hinfo[strtolower(trim($fs[0]))] , (array)trim($fs[1]) );
               else
                  $hinfo[strtolower(trim($fs[0]))] = trim($fs[1]);
              }
           }
    }
 return $hinfo;
}
//-------------------------------------------------------------------------------------------------

function _get_signature($accesskey,$securekey,&$header_array)
{
 $content="FetchUrl";
 $content.=$header_array["FetchUrl"];
 $content.="TimeStamp";
 $content.=$header_array['TimeStamp'];
 $content.="AccessKey";
 $content.=$header_array['AccessKey'];
 return base64_encode(hash_hmac('sha256',$content,$securekey,true));
}
//-------------------------------------------------------------------------------------------------

function _read_header($ch,$string)
{
 global $errno,$errmsg,$rheader;
 $rheader.=$string;
 $ret=explode(" ",$string);
 if(count($ret)==3 && $ret[0]=='HTTP/1.1')
   {
    if($ret[1]==200)
       $errno=0;
    else
       {
       $errno=$ret[1];
       $errmsg=$ret[2];
       }
   }
 return strlen($string);
}
//-------------------------------------------------------------------------------------------------

function _read_data($ch,$string)
{
 global $rdata;
 $rdata.=$string;
 return strlen($string);
}
//-------------------------------------------------------------------------------------------------

function _fetch_url($url,$accesskey,$securekey,&$header,&$error,$opt=NULL)
{
 global $errno,$errmsg,$rheader,$rdata;
 $rheader='';
 $rdata='';
 $errno=0;
 $errmsg='';
 $ch=curl_init();
 curl_setopt($ch,CURLOPT_HEADERFUNCTION,'_read_header');
 curl_setopt($ch,CURLOPT_WRITEFUNCTION,'_read_data');
 curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,3);
 curl_setopt($ch,CURLOPT_TIMEOUT,10);
 $header_array=array();
 if($opt && is_array($opt))
   {
    if(array_key_exists('username',$opt) && array_key_exists('password',$opt))
       curl_setopt($ch,CURLOPT_USERPWD,$opt['username'].':'.$opt['password']);
    if(array_key_exists('useragent',$opt))
       curl_setopt($ch,CURLOPT_USERAGENT,$opt['useragent']);
    if(array_key_exists('post',$opt))
      {
       curl_setopt($ch,CURLOPT_POST,true);
       curl_setopt($ch,CURLOPT_POSTFIELDS,$opt['post']);
      }
    if(array_key_exists('truncated',$opt))
       $header_array['AllowTruncated']=$opt['truncated'];

//    if(array_key_exists('connecttimeout',$opt))
//       $header_array['ConnectTimeout']=$opt['connecttimeout'];
//    if(array_key_exists('sendtimeout',$opt))
//       $header_array['SendTimeout']=$opt['sendtimeout'];
//    if(array_key_exists('readtimeout',$opt))
//       $header_array['ReadTimeout']=$opt['readtimeout'];

    if(array_key_exists('headers',$opt))
      {
       $headers=$opt['headers'];
       if(is_array($headers))
         {
          foreach($headers as $k => $v)
                  $header_array[$k]=$v;
         }
      }
   }//end if is_array
 $header_array['FetchUrl']=$url;
 $header_array['AccessKey']=$accesskey;
 $header_array['TimeStamp']=date('Y-m-d H:i:s');
 $header_array['Signature']=_get_signature($accesskey,$securekey,$header_array);

 $header_array2=array();
 foreach($header_array as $k => $v)
         array_push($header_array2,$k.': '.$v);

 curl_setopt($ch,CURLOPT_HTTPHEADER,$header_array2);
 curl_setopt($ch,CURLOPT_URL,SAE_FETCHURL_SERVICE_ADDRESS);
 curl_exec($ch);
 curl_close($ch);
 $header=$rheader;
 if($errno==0)
    return $rdata;
 $error=$errno.': '.$errmsg;
 return false;
}//end function fetchurl
//-------------------------------------------------------------------------------------------------

function fetch_url($url,$accesskey,$securekey,&$header,&$error,$opt=NULL)
{
 if($opt && is_array($opt) && array_key_exists('redirect',$opt) && $opt['redirect']==true)
   {
    $times=0;
    while(true)
         {
          $rt=_fetch_url($url,$accesskey,$securekey,$header,$error,$opt);
          if($rt==false)
             return $rt;
          $info=_header_info($header);
          $jump=false;
          if(isset($info['location']) && ($info['code']==301|| $info['code']==302) && $times<5)
            $jump=true;
          if($jump==true)
            {
             $times++;
             $url=$info['location'];
             continue;
            }
          return $rt;
         }//end while
   }//end if
 return _fetch_url($url,$accesskey,$securekey,$header,$error,$opt);
}
//-------------------------------------------------------------------------------------------------



if ( ! in_array("saemc", stream_get_wrappers()) )
    stream_wrapper_register("saemc", "SaeMemcacheWrapper");




class SaeMemcacheWrapper // implements WrapperInterface
{
    public $dir_mode = 16895 ; //040000 + 0222;
    public $file_mode = 33279 ; //0100000 + 0777;


    public function __construct()
    {
        $this->mc = memcache_init();
    }

    public function mc() {
        if ( !isset( $this->mc ) ) $this->mc = memcache_init();
        return $this->mc;
    }

    public function stream_open( $path , $mode , $options , &$opened_path)
    {
        $this->position = 0;
        $this->mckey = trim(substr($path, 8));
        $this->mode = $mode;
        $this->options = $options;

        if ( in_array( $this->mode, array( 'r', 'r+', 'rb' ) ) ) {
            if ( $this->mccontent = memcache_get( $this->mc, $this->mckey ) ) {
                $this->get_file_info( $this->mckey );
                $this->stat['mode'] = $this->stat[2] = $this->file_mode;
            } else {
                trigger_error("fopen({$path}): failed to read from Memcached: No such key.", E_USER_WARNING);
                return false;
            }
        } elseif ( in_array( $this->mode, array( 'a', 'a+', 'ab' ) ) ) {
            if ( $this->mccontent = memcache_get( $this->mc , $this->mckey ) ) {
                $this->get_file_info( $this->mckey );
                $this->stat['mode'] = $this->stat[2] = $this->file_mode;
                $this->position = strlen($this->mccontent);
            } else {
                $this->mccontent = '';
                $this->stat['ctime'] = $this->stat[10] = time();
            }
        } elseif ( in_array( $this->mode, array( 'x', 'x+', 'xb' ) ) ) {
            if ( !memcache_get( $this->mc , $this->mckey ) ) {
                $this->mccontent = '';
                $this->statinfo_init();
                $this->stat['ctime'] = $this->stat[10] = time();
            } else {
                trigger_error("fopen({$path}): failed to create at Memcached: Key exists.", E_USER_WARNING);
                return false;
            }
        } elseif ( in_array( $this->mode, array( 'w', 'w+', 'wb' ) ) ) {
            $this->mccontent = '';
            $this->statinfo_init();
            $this->stat['ctime'] = $this->stat[10] = time();
        } else {
            $this->mccontent = memcache_get( $this->mc , $this->mckey );
        }

        return true;
    }

    public function stream_read($count)
    {
        if (in_array($this->mode, array('w', 'x', 'a', 'wb', 'xb', 'ab') ) ) {
            return false;
        }


        $ret = substr( $this->mccontent , $this->position, $count);
        $this->position += strlen($ret);

        $this->stat['atime'] = $this->stat[8] = time();
        $this->stat['uid'] = $this->stat[4] = 0;
        $this->stat['gid'] = $this->stat[5] = 0;

        return $ret;
    }

    public function stream_write($data)
    {
        if ( in_array( $this->mode, array( 'r', 'rb' ) ) ) {
            return false;
        }

        $left = substr($this->mccontent, 0, $this->position);
        $right = substr($this->mccontent, $this->position + strlen($data));
        $this->mccontent = $left . $data . $right;

        if ( memcache_set( $this->mc , $this->mckey , $this->mccontent ) ) {
            $this->stat['mtime'] = $this->stat[9] = time();
            $this->position += strlen($data);
            return $this->stat['size'] = $this->stat[7] = strlen( $data );
        }
        else return false;
    }

    public function stream_close()
    {

        memcache_set( $this->mc , $this->mckey.'.meta' ,  serialize($this->stat)  );
        //memcache_close( $this->mc );
    }


    public function stream_eof()
    {

        return $this->position >= strlen( $this->mccontent  );
    }

    public function stream_tell()
    {

        return $this->position;
    }

    public function stream_seek($offset , $whence = SEEK_SET)
    {

        switch ($whence) {
        case SEEK_SET:

            if ($offset < strlen( $this->mccontent ) && $offset >= 0) {
                $this->position = $offset;
                return true;
            }
            else
                return false;

            break;

        case SEEK_CUR:

            if ($offset >= 0) {
                $this->position += $offset;
                return true;
            }
            else
                return false;

            break;

        case SEEK_END:

            if (strlen( $this->mccontent ) + $offset >= 0) {
                $this->position = strlen( $this->mccontent ) + $offset;
                return true;
            }
            else
                return false;

            break;

        default:

            return false;
        }
    }

    public function stream_stat()
    {
        return $this->stat;
    }

    // ============================================
    public function mkdir($path , $mode , $options)
    {
        $path = trim(substr($path, 8));


        //echo "回调mkdir\n";
        $path  = rtrim( $path  , '/' );

        $this->stat = $this->get_file_info( $path );
        $this->stat['ctime'] = $this->stat[10] = time();
        $this->stat['mode'] = $this->stat[2] = $this->dir_mode;

        //echo "生成新的stat数据" . print_r( $this->stat , 1 );

        memcache_set( $this->mc() , $path.'.meta' ,  serialize($this->stat)  );

        //echo "写入MC. key= " . $path.'.meta ' .  memcache_get( $this->mc , $path.'.meta'  );
        memcache_close( $this->mc );


        return true;
    }

    public function rename($path_from , $path_to)
    {
        $path_from = trim(substr($path_from, 8));
        $path_to = trim(substr($path_to, 8));


        memcache_set( $this->mc() , $path_to , memcache_get( $this->mc() , $path_from ) );
        memcache_set( $this->mc() , $path_to . '.meta' , memcache_get( $this->mc() , $path_from . '.meta' ) );
        memcache_delete( $this->mc() , $path_from );
        memcache_delete( $this->mc() , $path_from.'.meta' );
        clearstatcache( true );
        return true;
    }

    public function rmdir($path , $options)
    {
        $path = trim(substr($path, 8));


        $path  = rtrim( $path  , '/' );

        memcache_delete( $this->mc() , $path .'.meta'  );
        clearstatcache( true );
        return true;
    }

    public function unlink($path)
    {
        $path = trim(substr($path, 8));
        $path  = rtrim( $path  , '/' );

        memcache_delete( $this->mc() , $path );
        memcache_delete( $this->mc() , $path . '.meta' );
        clearstatcache( true );
        return true;
    }

    public function url_stat($path , $flags)
    {
        $path = trim(substr($path, 8));
        $path  = rtrim( $path  , '/' );

        if ( !$this->is_file_info_exists( $path ) ) {
            return false;
        } else {
            if ( $stat = memcache_get( $this->mc() , $path . '.meta' ) ) {
                $this->stat = unserialize($stat);
                if ( is_array($this->stat) ) {
                    if ( $this->stat['mode'] == $this->dir_mode || $c = memcache_get( $this->mc(), $path ) ) {
                        return $this->stat;
                    } else {
                        memcache_delete( $this->mc() , $path . '.meta' );
                    }
                }
            }
            return false;
        }
    }






    // ============================================

    public function is_file_info_exists( $path )
    {
        //echo "获取MC数据 key= " .  $path.'.meta' ;
        $d = memcache_get( $this->mc() , $path . '.meta' );
        //echo "\n返回数据为" . $d . "\n";
        return $d;
    }

    public function get_file_info( $path )
    {
        if ( $stat = memcache_get( $this->mc() , $path . '.meta' ) )
            return $this->stat =  unserialize($stat);
        else $this->statinfo_init();
    }

    public function statinfo_init( $is_file = true )
    {
        $this->stat['dev'] = $this->stat[0] = 0x8002;
        $this->stat['ino'] = $this->stat[1] = mt_rand(10000, PHP_INT_MAX);

        if( $is_file )
            $this->stat['mode'] = $this->stat[2] = $this->file_mode;
        else
            $this->stat['mode'] = $this->stat[2] = $this->dir_mode;

        $this->stat['nlink'] = $this->stat[3] = 0;
        $this->stat['uid'] = $this->stat[4] = 0;
        $this->stat['gid'] = $this->stat[5] = 0;
        $this->stat['rdev'] = $this->stat[6] = 0;
        $this->stat['size'] = $this->stat[7] = 0;
        $this->stat['atime'] = $this->stat[8] = 0;
        $this->stat['mtime'] = $this->stat[9] = 0;
        $this->stat['ctime'] = $this->stat[10] = 0;
        $this->stat['blksize'] = $this->stat[11] = 0;
        $this->stat['blocks'] = $this->stat[12] = 0;

    }

    public function dir_closedir() {
        return false;
    }

    public function dir_opendir($path, $options) {
        return false;
    }

    public function dir_readdir() {
        return false;
    }

    public function dir_rewinddir() {
        return false;
    }

    public function stream_cast($cast_as) {
        return false;
    }

    public function stream_flush() {
        return false;
    }

    public function stream_lock($operation) {
        return false;
    }

    public function stream_set_option($option, $arg1, $arg2) {
        return false;
    }

}





/* BEGIN *******************  Storage Wrapper By Elmer Zhang At 16/Mar/2010 14:47 ****************/

class SaeStorageWrapper // implements WrapperInterface
{
    private $writen = true;

    public function __construct()
    {
        $this->stor = new SaeStorage();
    }

    public function stor() {
        if ( !isset( $this->stor ) ) $this->stor = new SaeStorage();
    }

    public function stream_open( $path , $mode , $options , &$opened_path)
    {
        $pathinfo = parse_url($path);
        $this->domain = $pathinfo['host'];
        $this->file = ltrim(strstr($path, $pathinfo['path']), '/\\');
        $this->position = 0;
        $this->mode = $mode;
        $this->options = $options;

        // print_r("OPEN\tpath:{$path}\tmode:{$mode}\toption:{$option}\topened_path:{$opened_path}\n");

        if ( in_array( $this->mode, array( 'r', 'r+', 'rb' ) ) ) {
            if ( $this->fcontent = $this->stor->read($this->domain, $this->file) ) {
            } else {
                trigger_error("fopen({$path}): failed to read from Storage: No such domain or file.", E_USER_WARNING);
                return false;
            }
        } elseif ( in_array( $this->mode, array( 'a', 'a+', 'ab' ) ) ) {
            trigger_error("fopen({$path}): Sorry, saestor does not support appending", E_USER_WARNING);
            if ( $this->fcontent = $this->stor->read($this->domain, $this->file) ) {
            } else {
                trigger_error("fopen({$path}): failed to read from Storage: No such domain or file.", E_USER_WARNING);
                return false;
            }
        } elseif ( in_array( $this->mode, array( 'x', 'x+', 'xb' ) ) ) {
            if ( !$this->stor->getAttr($this->domain, $this->file) ) {
                $this->fcontent = '';
            } else {
                trigger_error("fopen({$path}): failed to create at Storage: File exists.", E_USER_WARNING);
                return false;
            }
        } elseif ( in_array( $this->mode, array( 'w', 'w+', 'wb' ) ) ) {
            $this->fcontent = '';
        } else {
            $this->fcontent = $this->stor->read($this->domain, $this->file);
        }

        return true;
    }

    public function stream_read($count)
    {
        if (in_array($this->mode, array('w', 'x', 'a', 'wb', 'xb', 'ab') ) ) {
            return false;
        }

        $ret = substr( $this->fcontent , $this->position, $count);
        $this->position += strlen($ret);

        return $ret;
    }

    public function stream_write($data)
    {
        if ( in_array( $this->mode, array( 'r', 'rb' ) ) ) {
            return false;
        }

        // print_r("WRITE\tcontent:".strlen($this->fcontent)."\tposition:".$this->position."\tdata:".strlen($data)."\n");

        $left = substr($this->fcontent, 0, $this->position);
        $right = substr($this->fcontent, $this->position + strlen($data));
        $this->fcontent = $left . $data . $right;

        //if ( $this->stor->write( $this->domain, $this->file, $this->fcontent ) ) {
        $this->position += strlen($data);
        if ( strlen( $data ) > 0 )
            $this->writen = false;

        return strlen( $data );
        //}
        //else return false;
    }

    public function stream_close()
    {
        if (!$this->writen) {
            $this->stor->write( $this->domain, $this->file, $this->fcontent );
            $this->writen = true;
        }
    }


    public function stream_eof()
    {

        return $this->position >= strlen( $this->fcontent  );
    }

    public function stream_tell()
    {

        return $this->position;
    }

    public function stream_seek($offset , $whence = SEEK_SET)
    {


        switch ($whence) {
        case SEEK_SET:

            if ($offset < strlen( $this->fcontent ) && $offset >= 0) {
                $this->position = $offset;
                return true;
            }
            else
                return false;

            break;

        case SEEK_CUR:

            if ($offset >= 0) {
                $this->position += $offset;
                return true;
            }
            else
                return false;

            break;

        case SEEK_END:

            if (strlen( $this->fcontent ) + $offset >= 0) {
                $this->position = strlen( $this->fcontent ) + $offset;
                return true;
            }
            else
                return false;

            break;

        default:

            return false;
        }
    }

    public function unlink($path)
    {
        self::stor();
        $pathinfo = parse_url($path);
        $this->domain = $pathinfo['host'];
        $this->file = ltrim(strstr($path, $pathinfo['path']), '/\\');

        clearstatcache( true );
        return $this->stor->delete( $this->domain , $this->file );
    }

    public function stream_flush() {
        if (!$this->writen) {
            $this->stor->write( $this->domain, $this->file, $this->fcontent );
            $this->writen = true;
        }

        return $this->writen;
    }

    public function stream_stat() {
        return array();
    }

    public function url_stat($path, $flags) {
        self::stor();
        $pathinfo = parse_url($path);
        $this->domain = $pathinfo['host'];
        $this->file = ltrim(strstr($path, $pathinfo['path']), '/\\');

        if ( $attr = $this->stor->getAttr( $this->domain , $this->file ) ) {
            $stat = array();
            $stat['dev'] = $stat[0] = 0x8001;
            $stat['ino'] = $stat[1] = 0;;
            $stat['mode'] = $stat[2] = 33279; //0100000 + 0777;
            $stat['nlink'] = $stat[3] = 0;
            $stat['uid'] = $stat[4] = 0;
            $stat['gid'] = $stat[5] = 0;
            $stat['rdev'] = $stat[6] = 0;
            $stat['size'] = $stat[7] = $attr['length'];
            $stat['atime'] = $stat[8] = 0;
            $stat['mtime'] = $stat[9] = $attr['datetime'];
            $stat['ctime'] = $stat[10] = $attr['datetime'];
            $stat['blksize'] = $stat[11] = 0;
            $stat['blocks'] = $stat[12] = 0;
            return $stat;
        } else {
            return false;
        }
    }

    public function dir_closedir() {
        return false;
    }

    public function dir_opendir($path, $options) {
        return false;
    }

    public function dir_readdir() {
        return false;
    }

    public function dir_rewinddir() {
        return false;
    }

    public function mkdir($path, $mode, $options) {
        return false;
    }

    public function rename($path_from, $path_to) {
        return false;
    }

    public function rmdir($path, $options) {
        return false;
    }

    public function stream_cast($cast_as) {
        return false;
    }

    public function stream_lock($operation) {
        return false;
    }

    public function stream_set_option($option, $arg1, $arg2) {
        return false;
    }

}


if ( in_array( "saestor", stream_get_wrappers() ) ) {
    stream_wrapper_unregister("saestor");
}
stream_wrapper_register( "saestor", "SaeStorageWrapper" )
    or die( "Failed to register protocol" );

/* END *********************  Storage Wrapper By Elmer Zhang At 16/Mar/2010 14:47 ****************/


/* BEGIN *******************  KVDB Wrapper By Elmer Zhang At 12/Dec/2011 12:37 ****************/

class SaeKVWrapper // implements WrapperInterface
{
    private $dir_mode = 16895 ; //040000 + 0222;
    private $file_mode = 33279 ; //0100000 + 0777;


    public function __construct() { }

    private function kv() {
        if ( !isset( $this->kv ) ) $this->kv = new SaeKV();
        $this->kv->init();
        return $this->kv;
    }

    private function open( $key ) {
        $value = $this->kv()->get( $key );
        if ( $value !== false && $this->unpack_stat(substr($value, 0, 20)) === true ) {
            $this->kvcontent = substr($value, 20);
            return true;
        } else {
            return false;
        }
    }

    private function save( $key ) {
        $this->stat['mtime'] = $this->stat[9] = time();
        if ( isset($this->kvcontent) ) {
            $this->stat['size'] = $this->stat[7] = strlen($this->kvcontent);
            $value = $this->pack_stat() . $this->kvcontent;
        } else {
            $this->stat['size'] = $this->stat[7] = 0;
            $value = $this->pack_stat();
        }
        return $this->kv()->set($key, $value);
    }

    private function unpack_stat( $str ) {
        $arr = unpack("L5", $str);

        // check if valid
        if ( $arr[1] < 10000 ) return false;
        if ( !in_array($arr[2], array( $this->dir_mode, $this->file_mode ) ) ) return false;
        if ( $arr[4] > time() ) return false;
        if ( $arr[5] > time() ) return false;

        $this->stat['dev'] = $this->stat[0] = 0x8003;
        $this->stat['ino'] = $this->stat[1] = $arr[1];
        $this->stat['mode'] = $this->stat[2] = $arr[2];
        $this->stat['nlink'] = $this->stat[3] = 0;
        $this->stat['uid'] = $this->stat[4] = 0;
        $this->stat['gid'] = $this->stat[5] = 0;
        $this->stat['rdev'] = $this->stat[6] = 0;
        $this->stat['size'] = $this->stat[7] = $arr[3];
        $this->stat['atime'] = $this->stat[8] = 0;
        $this->stat['mtime'] = $this->stat[9] = $arr[4];
        $this->stat['ctime'] = $this->stat[10] = $arr[5];
        $this->stat['blksize'] = $this->stat[11] = 0;
        $this->stat['blocks'] = $this->stat[12] = 0;

        return true;
    }

    private function pack_stat( ) {
        $str = pack("LLLLL", $this->stat['ino'], $this->stat['mode'], $this->stat['size'], $this->stat['ctime'], $this->stat['mtime']);
        return $str;
    }

    public function stream_open( $path , $mode , $options , &$opened_path)
    {
        $this->position = 0;
        $this->kvkey = rtrim(trim(substr(trim($path), 8)), '/');
        $this->mode = $mode;
        $this->options = $options;

        if ( in_array( $this->mode, array( 'r', 'r+', 'rb' ) ) ) {
            if ( $this->open( $this->kvkey ) === false ) {
                trigger_error("fopen({$path}): No such key in KVDB.", E_USER_WARNING);
                return false;
            }
        } elseif ( in_array( $this->mode, array( 'a', 'a+', 'ab' ) ) ) {
            if ( $this->open( $this->kvkey ) === true ) {
                $this->position = strlen($this->kvcontent);
            } else {
                $this->kvcontent = '';
                $this->statinfo_init();
            }
        } elseif ( in_array( $this->mode, array( 'x', 'x+', 'xb' ) ) ) {
            if ( $this->open( $this->kvkey ) === false ) {
                $this->kvcontent = '';
                $this->statinfo_init();
            } else {
                trigger_error("fopen({$path}): Key exists in KVDB.", E_USER_WARNING);
                return false;
            }
        } elseif ( in_array( $this->mode, array( 'w', 'w+', 'wb' ) ) ) {
            $this->kvcontent = '';
            $this->statinfo_init();
        } else {
            $this->open( $this->kvkey );
        }

        return true;
    }

    public function stream_read($count)
    {
        if (in_array($this->mode, array('w', 'x', 'a', 'wb', 'xb', 'ab') ) ) {
            return false;
        }

        $ret = substr( $this->kvcontent , $this->position, $count);
        $this->position += strlen($ret);

        return $ret;
    }

    public function stream_write($data)
    {
        if ( in_array( $this->mode, array( 'r', 'rb' ) ) ) {
            return false;
        }

        $left = substr($this->kvcontent, 0, $this->position);
        $right = substr($this->kvcontent, $this->position + strlen($data));
        $this->kvcontent = $left . $data . $right;

        if ( $this->save( $this->kvkey ) === true ) {
            $this->position += strlen($data);
            return strlen( $data );
        } else return false;
    }

    public function stream_close()
    {
        $this->save( $this->kvkey );
    }


    public function stream_eof()
    {

        return $this->position >= strlen( $this->kvcontent  );
    }

    public function stream_tell()
    {

        return $this->position;
    }

    public function stream_seek($offset , $whence = SEEK_SET)
    {

        switch ($whence) {
        case SEEK_SET:

            if ($offset < strlen( $this->kvcontent ) && $offset >= 0) {
                $this->position = $offset;
                return true;
            }
            else
                return false;

            break;

        case SEEK_CUR:

            if ($offset >= 0) {
                $this->position += $offset;
                return true;
            }
            else
                return false;

            break;

        case SEEK_END:

            if (strlen( $this->kvcontent ) + $offset >= 0) {
                $this->position = strlen( $this->kvcontent ) + $offset;
                return true;
            }
            else
                return false;

            break;

        default:

            return false;
        }
    }

    public function stream_stat()
    {
        return $this->stat;
    }

    // ============================================
    public function mkdir($path , $mode , $options)
    {
        $path = rtrim(trim(substr(trim($path), 8)), '/');

        if ( $this->open( $path ) === false ) {
            $this->statinfo_init( false );
            return $this->save( $path );
        } else {
            trigger_error("mkdir({$path}): Key exists in KVDB.", E_USER_WARNING);
            return false;
        }
    }

    public function rename($path_from , $path_to)
    {
        $path_from = rtrim(trim(substr(trim($path_from), 8)), '/');
        $path_to = rtrim(trim(substr(trim($path_to), 8)), '/');

        if ( $this->open( $path_from ) === true ) {
            clearstatcache( true );
            return $this->save( $path_to );
        } else {
            trigger_error("rename({$path_from}, {$path_to}): No such key in KVDB.", E_USER_WARNING);
            return false;
        }
    }

    public function rmdir($path , $options)
    {
        $path = rtrim(trim(substr(trim($path), 8)), '/');

        clearstatcache( true );
        return $this->kv()->delete($path);
    }

    public function unlink($path)
    {
        $path = rtrim(trim(substr(trim($path), 8)), '/');

        clearstatcache( true );
        return $this->kv()->delete($path);
    }

    public function url_stat($path , $flags)
    {
        $path = rtrim(trim(substr(trim($path), 8)), '/');

        if ( $this->open( $path ) !== false ) {
            return $this->stat;
        } else {
            return false;
        }
    }






    // ============================================

    private function statinfo_init( $is_file = true )
    {
        $this->stat['dev'] = $this->stat[0] = 0x8003;
        $this->stat['ino'] = $this->stat[1] = crc32(SAE_APPNAME . '/' . $this->kvkey);

        if( $is_file )
            $this->stat['mode'] = $this->stat[2] = $this->file_mode;
        else
            $this->stat['mode'] = $this->stat[2] = $this->dir_mode;

        $this->stat['nlink'] = $this->stat[3] = 0;
        $this->stat['uid'] = $this->stat[4] = 0;
        $this->stat['gid'] = $this->stat[5] = 0;
        $this->stat['rdev'] = $this->stat[6] = 0;
        $this->stat['size'] = $this->stat[7] = 0;
        $this->stat['atime'] = $this->stat[8] = 0;
        $this->stat['mtime'] = $this->stat[9] = time();
        $this->stat['ctime'] = $this->stat[10] = 0;
        $this->stat['blksize'] = $this->stat[11] = 0;
        $this->stat['blocks'] = $this->stat[12] = 0;

    }

    public function dir_closedir() {
        return false;
    }

    public function dir_opendir($path, $options) {
        return false;
    }

    public function dir_readdir() {
        return false;
    }

    public function dir_rewinddir() {
        return false;
    }

    public function stream_cast($cast_as) {
        return false;
    }

    public function stream_flush() {
        return false;
    }

    public function stream_lock($operation) {
        return false;
    }

    public function stream_set_option($option, $arg1, $arg2) {
        return false;
    }

}

if ( ! in_array("saekv", stream_get_wrappers()) )
    stream_wrapper_register("saekv", "SaeKVWrapper");

/* END *********************  KVDB Wrapper By Elmer Zhang At 12/Dec/2011 12:37 ****************/



/* START *********************  Supported for AppCookie By Elmer Zhang At 13/Jun/2010 15:49 ****************/
$appSettings = array();
if (isset($_SERVER['HTTP_APPCOOKIE']) && $_SERVER['HTTP_APPCOOKIE']) {
    $appCookie = trim($_SERVER['HTTP_APPCOOKIE']);
    $tmpSettings = array_filter(explode(';', $appCookie));
    if ($tmpSettings) {
        foreach($tmpSettings as $setting) {
            $tmp = explode('=', $setting);
            $appSettings[$tmp[0]] = $tmp[1];
        }
    }
}

if (isset($appSettings['xhprof']) && in_array($_SERVER['HTTP_APPVERSION'], explode(',', $appSettings['xhprof']))) {
    sae_xhprof_start();
    register_shutdown_function("sae_xhprof_end");
}

if (isset($appSettings['debug']) && in_array($_SERVER['HTTP_APPVERSION'], explode(',', $appSettings['debug']))) {
    sae_set_display_errors(true);
}

unset($appSettings);
unset($appCookie);
unset($tmpSettings);
unset($tmp);

/* END *********************  Supported for AppCookie By Elmer Zhang At 13/Jun/2010 16:04 ****************/