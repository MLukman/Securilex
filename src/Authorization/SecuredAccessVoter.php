<?php

namespace Securilex\Authorization;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class SecuredAccessVoter extends Voter
{

    /**
     * {@inheritdoc}
     */
    protected function supports($attribute, $subject)
    {
        return ($subject instanceof SecuredAccessInterface);
    }

    /**
     * {@inheritdoc}
     */
    protected function voteOnAttribute($attribute, $subject,
                                       TokenInterface $token)
    {
        /* @var $subject SecuredAccessInterface */
        if ($subject->isUsernameAllowed($token->getUsername(), $attribute)) {
            return true;
        }

        foreach ($token->getRoles() as $role) {
            if ($subject->isRoleAllowed($role->getRole(), $attribute)) {
                return true;
            }
        }

        return false;
    }
}