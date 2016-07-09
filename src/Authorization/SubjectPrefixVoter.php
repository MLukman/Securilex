<?php

namespace Securilex\Authorization;

use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class SubjectPrefixVoter extends Voter
{
    protected $subjectPrefixes = array();

    static public function instance()
    {
        static $instance = null;
        if (!$instance) {
            $instance = new static();
        }
        return $instance;
    }

    public function addSubjectPrefix($subjectPrefix, $roles)
    {
        if (!is_array($roles)) {
            $roles = array($roles);
        }
        if (is_array($subjectPrefix)) {
            foreach ($subjectPrefix as $oneSubjectPrefix) {
                $this->addSubjectPrefix($oneSubjectPrefix, $roles);
            }
        } else {
            if (isset($this->subjectPrefixes[$subjectPrefix])) {
                $this->subjectPrefixes[$subjectPrefix] = array_merge($this->subjectPrefixes[$subjectPrefix],
                    $roles);
            } else {
                $this->subjectPrefixes[$subjectPrefix] = $roles;
            }
        }
        return $this;
    }

    protected function supports($attribute, $subject)
    {
        return (substr($attribute, 0, 6) == 'prefix');
    }

    protected function voteOnAttribute($attribute, $subject,
                                       \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token)
    {
        $granted = true;
        $uroles  = array();
        foreach ($token->getRoles() as $role) {
            $uroles[] = $role->getRole();
        }
        foreach ($this->subjectPrefixes as $prefix => $proles) {
            if (substr($subject, 0, strlen($prefix)) != $prefix) {
                continue;
            }
            $granted = false;
            if (count(array_intersect($uroles, $proles)) > 0) {
                return true;
            }
        }
        return $granted;
    }
}