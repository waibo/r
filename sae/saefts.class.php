<?php
/**
 * SAE 全文检索服务 
 *
 * @package sae 
 * @version $Id$
 * @author Elmer Zhang
 */



/**
 * SAE 全文检索服务<br />
 *
 * <code>
 * $fts = new SaeFTS();
 *
 * $ret = $fts->addDoc(1, 'content test1');    // 添加id为1, 内容为'content test1'的文档
 * if ( $ret === false ) var_dump( $fts->errno(), $fts->errmsg());
 *
 * $ret = $fts->addDoc(2, 'content test1');    // 添加id为2，内容为'content test1'的文档
 * if ( $ret === false ) var_dump( $fts->errno(), $fts->errmsg());
 *
 * $ret = $fts->modifyDoc(2, 'content test2');    // 修改id为2的文档，内容修改为'content test2'
 * if ( $ret === false ) var_dump( $fts->errno(), $fts->errmsg());
 *
 * $ret = $fts->deleteDoc(1);        // 删除id为1的文档
 * if ( $ret === false ) var_dump( $fts->errno(), $fts->errmsg());
 *
 * $ret = $fts->addDoc(3, 'content test2 test3');        // 添加id为3，内容为'content test2 test3'的文档
 * if ( $ret === false ) var_dump( $fts->errno(), $fts->errmsg());
 *
 * $ret = $fts->search('test');        // 搜索包含'test'的文档
 * if ( $ret === false ) {
 *     var_dump( $fts->errno(), $fts->errmsg());
 * } else {
 *     print_r( $ret );     
 * }
 *
 * </code>
 *
 * 错误码参考：
 *  - errno: 0         成功
 *  - errno: -1     参数错误
 *  - errno: -4     系统内部错误
 *  - errno: 607     服务未初始化
 *
 * @package sae
 * @author Elmer Zhang
 *
 */
class SaeFTS extends SaeObject
{
    private $_errno = SAE_Success;
    private $_errmsg = "OK";
    private $_errmsgs = array(
            -1 => "invalid parameters",
            -4 => "internal error",
            607 => "service is not enabled",
            );

    /**
     * @ignore
     */
    const searchurl = "http://fts.sae.sina.com.cn/SaeSearch_v1/Search.php";

    /**
     * @ignore
     */
    const manageurl = "http://fts.sae.sina.com.cn/SaeSearch_v1/IndexManage.php";

    /**
     * 构造对象
     *
     */
    function __construct() {
        $this->_accessKey = SAE_ACCESSKEY;
    }

    /**
     * 添加文档
     *
     * 文档id号相同的文档不可重复添加，如需修改已存在文档，请使用modifyDoc
     * 
     * @param int $docid 文档的id号为整数。
     * @param string $content 索要索引的文档内容。
     * @return bool 成功返回true，失败返回false.
     * @author Elmer Zhang
     */
    function addDoc( $docid, $content ) {

        if ( !is_int($docid) && !ctype_digit($docid) ) {
            $this->_errno = -1;
            $this->_errmsg = 'docid must be an integer';
            return false;
        }

        if ( trim($content) == '' ) {
            $this->_errno = -1;
            $this->_errmsg = 'content can not be empty';
            return false;
        }

        $post = array();
        $params = array();
        $params['cmd'] = 'adddoc';
        $params['userid'] = $this->_accessKey;
        $params['docid'] = intval($docid);
        $post['content'] = $content;


        $ret = $this->postData(self::manageurl, $post, $params);

        return $ret;
    }

    /**
     * 修改文档
     * 
     * @param int $docid 文档的id号。
     * @param string $content 索要索引的文档内容。
     * @return bool 成功返回true，失败返回false.
     * @author Elmer Zhang
     */
    function modifyDoc( $docid, $content ) {

        if ( !is_int($docid) && !ctype_digit($docid) ) {
            $this->_errno = -1;
            $this->_errmsg = 'docid must be an integer';
            return false;
        }

        if ( trim($content) == '' ) {
            $this->_errno = -1;
            $this->_errmsg = 'content can not be empty';
            return false;
        }

        $post = array();
        $params = array();
        $params['cmd'] = 'modifydoc';
        $params['userid'] = $this->_accessKey;
        $params['docid'] = intval($docid);
        $post['content'] = $content;


        $ret = $this->postData(self::manageurl, $post, $params);

        return $ret;
    }

    /**
     * 删除文档
     * 
     * @param int $docid 文档的id号。
     * @return bool 成功返回true，失败返回false.
     * @author Elmer Zhang
     */
    function deleteDoc( $docid ) {

        if ( !is_int($docid) && !ctype_digit($docid) ) {
            $this->_errno = -1;
            $this->_errmsg = 'docid must be an integer';
            return false;
        }

        $post = array();
        $params = array();
        $params['cmd'] = 'deletedoc';
        $params['userid'] = $this->_accessKey;
        $params['docid'] = intval($docid);

        $ret = $this->postData(self::manageurl, $post, $params);

        return $ret;
    }

    /**
     * 搜索文档
     *
     * 检索规则：
     *  - “+”:表示关键词的AND的关系。
     *  - “-“:表示关键词不再检索结果中。
     * 例如：
     *  - 当我们要搜索同时出现串a、串b但不包含串c的所有文档，检索串为："a+b+-c"
     * 
     * @param string $q 检索串。
     * @return array|bool 成功返回检索结果，失败返回false
     * @author Elmer Zhang
     */
    function search( $q ) {

        $post = array();
        $params = array();
        $params['userid'] = $this->_accessKey;
        $params['q'] = $q;

        $ret = $this->postData(self::searchurl, $post, $params);

        return $ret;
    }

    /**
     * 取得错误码
     *
     * @return int
     * @author Elmer Zhang
     */
    public function errno() {
        return $this->_errno;
    }

    /**
     * 取得错误信息
     *
     * @return string
     * @author Elmer Zhang
     */
    public function errmsg() {
        return $this->_errmsg;
    }

    private function postData($baseurl, $post, $params) {
        $url = $baseurl . '?' . http_build_query( $params );
        $s = curl_init();
        if (is_array($post)) {
            $post = http_build_query($post);
        }
        curl_setopt($s,CURLOPT_URL,$url);
        curl_setopt($s,CURLOPT_HTTP_VERSION,CURL_HTTP_VERSION_1_0);
        curl_setopt($s,CURLOPT_TIMEOUT,5);
        curl_setopt($s,CURLOPT_RETURNTRANSFER,true);
        curl_setopt($s,CURLINFO_HEADER_OUT, true);
        curl_setopt($s,CURLOPT_POST,true);
        curl_setopt($s,CURLOPT_POSTFIELDS,$post); 
        $ret = curl_exec($s);
        $info = curl_getinfo($s);

        //var_dump($info, $ret);

        if(empty($info['http_code'])) {
            $this->_errno = -4;
            $this->_errmsg = "fulltext search service internal error";
        } else if($info['http_code'] == 607) {
            $this->_errno = 607;
            $this->_errmsg = $this->_errmsgs[607];
        } else if($info['http_code'] != 200) {
            $this->_errno = -1;
            $this->_errmsg = $this->_errmsgs[-4];
        } else {
            if($info['size_download'] == 0) { // get MailError header
                $this->_errno = SAE_ErrInternal;
                $this->_errmsg = "fulltext search service internal error";
            } else {
                $array = json_decode(trim($ret), true);
                if ( $array['errno'] !== 0 ) {
                    $this->_errno = $array['errno'];
                    $this->_errmsg = $array['errmsg'];

                    return false;
                } else {
                    $this->_errno = SAE_Success;
                    $this->_errmsg = 'OK';

                    if ( isset($array['result']) ) {
                        return $array['result'];
                    } else {
                        return true;
                    }
                }
            }
        }
        return false;
    }

}