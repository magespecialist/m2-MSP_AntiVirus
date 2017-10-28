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
use Magento\Framework\Filesystem\Io\File;
use MSP\AntiVirus\Api\AntiVirusInterface;
use Magento\Framework\App\RequestInterface;
use MSP\SecuritySuiteCommon\Api\AlertInterface;
use Socket\Raw\Socket;

class AntiVirus implements AntiVirusInterface
{
    const BLOCK_SIZE = 16384;
    const TIMEOUT = 30;

    private $minSize;

    /**
     * @var RequestInterface
     */
    private $request;

    /**
     * @var Socket
     */
    private $clamSocket = null;

    /**
     * @var ScopeConfigInterface
     */
    private $scopeConfig;

    /**
     * @var File
     */
    private $file;

    /**
     * @var AlertInterface
     */
    private $alert;

    public function __construct(
        RequestInterface $request,
        ScopeConfigInterface $scopeConfig,
        AlertInterface $alert,
        File $file
    ) {
        $this->request = $request;
        $this->scopeConfig = $scopeConfig;
        $this->file = $file;
        $this->alert = $alert;
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
     * Get Anti Virus socket instance
     * @return Socket
     */
    private function getAntiVirus()
    {
        if ($this->clamSocket === null) {
            try {
                $unix = $this->scopeConfig->getValue(AntiVirusInterface::XML_PATH_SOCKET);
                // @codingStandardsIgnoreStart
                $this->clamSocket = (new \Socket\Raw\Factory())->createClient($unix);
                // @codingStandardsIgnoreEnd
                $this->avCommand('IDSESSION');
            } catch (\Socket\Raw\Exception $e) {
                $this->clamSocket = false;
            }
        }

        return $this->clamSocket;
    }

    /**
     * Directly send a command to AV engine
     * @param string $command
     */
    private function avCommand($command)
    {
        $this->avSend("n$command\n");
    }

    /**
     * Directly send a command to AV engine
     * @param string $message
     */
    private function avSend($message)
    {
        if ($clamSocket = $this->getAntiVirus()) {
            $clamSocket->send($message, MSG_DONTROUTE);
        }
    }

    /**
     * Get minimum string size to activate check
     * @return int
     */
    private function getMinSize()
    {
        if ($this->minSize === null) {
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
        $response = $this->receiveResponse();

        return $response;
    }

    /**
     * Read AV response
     * @return null|string
     */
    private function readResponse()
    {
        $clamSocket = $this->getAntiVirus();
        $result = null;

        if ($clamSocket) {
            while (true) {
                if ($clamSocket->selectRead(static::TIMEOUT)) {
                    $res = $clamSocket->read(static::BLOCK_SIZE);

                    if ($res === "") {
                        break;
                    }
                    $result .= $res;

                    if (strcmp(substr($result, -1), "\n") == 0) {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        return $result;
    }

    /**
     * Receive and parse response from AV engine
     * @return null|string
     * @throws LocalizedException
     */
    private function receiveResponse()
    {
        if ($this->getAntiVirus()) {
            $result = $this->readResponse();

            if ($result) {
                $result = trim($result);
            }

            if (preg_match('/^[^:]+:[^:]+:(.+)$/', $result, $matches)) {
                $response = $matches[1];
            } else {
                throw new LocalizedException(__('Invalid ClamAV response'));
            }

            $response = trim($response);

            if ($response == 'OK') {
                return false;
            }

            if (preg_match('/\s+ERROR$/', $response)) {
                $this->alert->event(
                    'MSP_AntiVirus',
                    'Error while trying to scan file: ' . $response,
                    AlertInterface::LEVEL_ERROR
                );
                throw new LocalizedException(__('Error while trying to scan file: ' . $response));
            }

            if (!preg_match('/(.+?)\s+FOUND$/', $response, $matches)) {
                $this->alert->event(
                    'MSP_AntiVirus',
                    'Received invalid ClamAV response: ' . $response,
                    AlertInterface::LEVEL_ERROR
                );
                throw new LocalizedException(__('Invalid ClamAV engine response'));
            }

            return $matches[1];
        } else {
            return false;
        }
    }

    /**
     * Scan file and return false if no virus has been detected
     * @param string $file
     * @return array|false
     */
    public function scanFile($file)
    {
        if (!$file) {
            return false;
        }

        try {
            return $this->scanString($this->file->read($file));
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Perform a recursive file scan on request
     * @param array $files
     * @return array|false
     */
    private function recursiveFileRequestScan(array $files)
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
    private function recursiveParamRequestScan($params)
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

        if (!empty($files)) {
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
