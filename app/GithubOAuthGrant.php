<?php namespace App;

use Illuminate\Support\Facades\Auth;

class GithubOAuthGrant
{
  public function verify($username, $password)
  {
      if (Auth::user()) {
          return Auth::user()->id;
      }

      return false;
  }
}
