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
    const BLOCK_SIZE = 16384;
    const TIMEOUT = 30;

    /**
     * @var RequestInterface
     */
    private $request;

    /**
     * @var Socket
     */
    protected $av = null;

    /**
     * @var ScopeConfigInterface
     */
    private $scopeConfig;

    protected $minSize;

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
        return !!$this->scopeConfig->getValue(AntiVirusInterface::XML_PATH_ENABLED);
    }

    /**
     * Get antivirus instance
     * @return Socket
     */
    protected function getAntiVirus()
    {
        if (is_null($this->av)) {
            try {
                $unix = $this->scopeConfig->getValue(AntiVirusInterface::XML_PATH_SOCKET);
                $this->av = (new \Socket\Raw\Factory())->createClient($unix);
                $this->avCommand('IDSESSION');
            } catch (\Socket\Raw\Exception $e) {
                $this->av = false;
            }
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
        if ($av = $this->getAntiVirus()) {
            $av->send($message, MSG_DONTROUTE);
        }
    }

    /**
     * Get minimum string size to activate check
     * @return int
     */
    protected function getMinSize()
    {
        if (is_null($this->minSize)) {
            $this->minSize = max(1, $this->scopeConfig->getValue(AntiVirusInterface::XML_PATH_MIN_SIZE));
        }

        return $this->minSize;
    }

    /**
     * Scan string and return false if no virus has been detected
     * @param $string
     * @return string|false
     */
    public function scanString($string)
    {
        if (strlen($string) < $this->getMinSize()) {
            return false;
        }

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
        if ($av = $this->getAntiVirus()) {

            $result = null;

            while (true) {
                if ($av->selectRead(static::TIMEOUT)) {
                    $rt =$av->read(static::BLOCK_SIZE);
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
        } else {
            return false;
        }
    }

    /**
     * Scan file and return false if no virus has been detected
     * @param $file
     * @return array|false
     */
    public function scanFile($file)
    {
        if (!$file) {
            return false;
        }

        // Using file_get_contents to avoid permission issues
        try {
            return $this->scanString(file_get_contents($file));
        } catch (\Exception $e) {
            return false;
        }
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

    /**
     * Return true if ClamAV connection can be established
     * @return bool
     */
    public function testConnection()
    {
        return !!$this->getAntiVirus();
    }
}
