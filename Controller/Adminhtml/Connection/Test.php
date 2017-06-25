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

namespace MSP\AntiVirus\Controller\Adminhtml\Connection;

use Magento\Framework\App\Action\Context;
use MSP\AntiVirus\Api\AntiVirusInterface;

class Test extends \Magento\Framework\App\Action\Action
{
    /**
     * @var AntiVirusInterface
     */
    private $antiVirus;

    public function __construct(
        Context $context,
        AntiVirusInterface $antiVirus
    ) {
        parent::__construct($context);
        $this->antiVirus = $antiVirus;
    }

    public function execute()
    {
        if ($this->antiVirus->testConnection()) {
            $this->messageManager->addSuccessMessage('Connection established');
        } else {
            $this->messageManager->addErrorMessage('Could not establish a connection');
        }

        $this->_redirect($this->_redirect->getRefererUrl());
    }
}