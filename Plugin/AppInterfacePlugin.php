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

namespace MSP\AntiVirus\Plugin;

use Magento\Framework\App\State;
use Magento\Framework\AppInterface;
use Magento\Framework\App\RequestInterface;
use MSP\AntiVirus\Api\AntiVirusInterface;
use MSP\SecuritySuiteCommon\Api\LockDownInterface;
use MSP\SecuritySuiteCommon\Api\LogManagementInterface;
use Magento\Framework\Event\ManagerInterface as EventInterface;

class AppInterfacePlugin
{
    /**
     * @var RequestInterface
     */
    private $request;

    /**
     * @var AntiVirusInterface
     */
    private $antiVirus;

    /**
     * @var State
     */
    private $state;

    /**
     * @var EventInterface
     */
    private $event;

    /**
     * @var LockDownInterface
     */
    private $lockDown;


    public function __construct(
        RequestInterface $request,
        State $state,
        AntiVirusInterface $antiVirus,
        LockDownInterface $lockDown,
        EventInterface $event
    ) {
        $this->request = $request;
        $this->antiVirus = $antiVirus;
        $this->state = $state;
        $this->event = $event;
        $this->lockDown = $lockDown;
    }

    /**
     * Return true if content should be checked
     * @return bool
     */
    protected function shouldCheck()
    {
        return in_array($this->request->getMethod(), ['PUT', 'POST']);
    }

    public function aroundLaunch(AppInterface $subject, \Closure $proceed)
    {
        // We are creating a plugin for AppInterface to make sure we can perform an AV scan early in the code.
        // A predispatch observer is not an option.

        if ($this->antiVirus->isEnabled() && $this->shouldCheck()) {
            $res = $this->antiVirus->scanRequest();

            if ($res) {
                $this->event->dispatch(LogManagementInterface::EVENT_ACTIVITY, [
                    'module' => 'MSP_AntiVirus',
                    'message' => 'Found ' . $res,
                    'action' => 'stop',
                ]);

                $this->state->setAreaCode('frontend');

                return $this->lockDown->doHttpLockdown(__('Malware found: %1', $res));
            }
        }

        return $proceed();
    }
}
