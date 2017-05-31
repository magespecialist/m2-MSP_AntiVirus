<?php
/**
 * MageSpecialist
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is bundled with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to info@magespecialist.it so we can send you a copy immediately.
 *
 * @category   MSP
 * @package    MSP_AntiVirus
 * @copyright  Copyright (c) 2017 Skeeller srl (http://www.magespecialist.it)
 * @license    http://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

namespace MSP\AntiVirus\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Exception\LocalizedException;
use MSP\AntiVirus\Api\AntiVirusInterface;
use Magento\Framework\App\RequestInterface;
use Socket\Raw\Socket;

class AntiVirus implements AntiVirusInterface
{
    const BLOCK_SIZE = 8192;
    const TIMEOUT = 30;

    const XML_PATH_ENABLED = 'msp_securitysuite/antivirus/enabled';
    const XML_PATH_SOCKET = 'msp_securitysuite/antivirus/socket';

    /**
     * @var RequestInterface
     */
    private $request;

    /**
     * @var Socket
     */
    protected $av;

    /**
     * @var ScopeConfigInterface
     */
    private $scopeConfig;

    public function __construct(
        RequestInterface $request,
        ScopeConfigInterface $scopeConfig
    ) {
        $this->request = $request;
        $this->scopeConfig = $scopeConfig;
    }

    /**
     * Return true if AV is enabled
     * @return bool
     */
    public function isEnabled()
    {
        return !!$this->scopeConfig->getValue(static::XML_PATH_ENABLED);
    }

    /**
     * Get antivirus instance
     * @return Socket
     */
    protected function getAntiVirus()
    {
        if (!$this->av) {
            $unix = $this->scopeConfig->getValue(static::XML_PATH_SOCKET);
            $this->av = (new \Socket\Raw\Factory())->createClient($unix);
            $this->avCommand('IDSESSION');
        }

        return $this->av;
    }

    /**
     * Directly send a command to AV engine
     * @param $command
     */
    protected function avCommand($command)
    {
        $this->avSend("n$command\n");
    }

    /**
     * Directly send a command to AV engine
     * @param $message
     */
    protected function avSend($message)
    {
        $this->getAntiVirus()->send($message, MSG_DONTROUTE);
    }

    /**
     * Scan string and return false if no virus has been detected
     * @param $string
     * @return string|false
     */
    public function scanString($string)
    {
        $this->avCommand("INSTREAM");

        $chunksLeft = $string;
        while (strlen($chunksLeft) > 0) {
            $chunk = substr($chunksLeft, 0, static::BLOCK_SIZE);
            $chunksLeft = substr($chunksLeft, static::BLOCK_SIZE);
            $size = pack('N', strlen($chunk));
            $this->avSend($size);
            $this->avSend($chunk);
        }

        $this->avSend(pack('N', 0));
        $response = $this->avRecv();

        return $response;
    }

    /**
     * Read response from AV engine
     * @return null|string
     * @throws LocalizedException
     */
    protected function avRecv()
    {
        $result = null;

        while (true) {
            if ($this->av->selectRead(static::TIMEOUT)) {
                $rt = $this->getAntiVirus()->read(static::BLOCK_SIZE);
                if ($rt === "") {
                    break;
                }
                $result .= $rt;
                if (strcmp(substr($result, -1), "\n") == 0) {
                    break;
                }
            } else {
                break;
            }
        }

        if ($result) {
            $result = trim($result);
        }

        list($id, $foo, $response) = preg_split('/\s*:\s/', $result, 3);
        if ($response == 'OK') {
            return false;
        }

        if (preg_match('/\s+ERROR$/', $response)) {
            throw new LocalizedException(__('Error while trying to scan file: ' . $response));
        }

        if (!preg_match('/(.+?)\s+FOUND$/', $response, $matches)) {
            throw new LocalizedException(__('Invalid antivirus engine response'));
        }

        return $matches[1];
    }

    /**
     * Scan file and return false if no virus has been detected
     * @param $file
     * @return array|false
     */
    public function scanFile($file)
    {
        // Using file_get_contents to avoid permission issues
        return $this->scanString(file_get_contents($file));
    }

    /**
     * Perform a recursive file scan on request
     * @param array $files
     * @return array|false
     */
    protected function recursiveFileRequestScan(array $files)
    {
        if (isset($files['tmp_name']) && !is_array($files['tmp_name'])) {
            return $this->scanFile($files['tmp_name']);
        }

        foreach ($files as $file) {
            $res = $this->recursiveFileRequestScan($file);
            if ($res !== false) {
                return $res;
            }
        }

        return false;
    }

    /**
     * Perform a recursive file scan on request
     * @param $params
     * @return array|false
     */
    protected function recursiveParamRequestScan($params)
    {
        if (!is_array($params)) {
            return $this->scanString($params);
        }

        foreach ($params as $param) {
            $res = $this->recursiveParamRequestScan($param);
            if ($res !== false) {
                return $res;
            }
        }

        return false;
    }

    /**
     * Scan HTTP request and return false if no virus has been detected
     * @return array|false
     */
    public function scanRequest()
    {
        // Scan for files
        $files = $this->request->getFiles();
        if (count($files)) {
            foreach ($files as $file) {
                $res = $this->recursiveFileRequestScan($file);
                if ($res !== false) {
                    return $res;
                }
            }
        }

        // Scan for strings
        $params = $this->request->getParams();
        $res = $this->recursiveParamRequestScan($params);
        if ($res !== false) {
            return $res;
        }

        return false;
    }
}
