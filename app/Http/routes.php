<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It's a breeze. Simply tell Laravel the URIs it should respond to
| and give it the controller to call when that URI is requested.
|
*/
Route::get('/login', function() {
  return Socialite::with('github')->redirect();
});


Route::get('/session', function (Illuminate\Http\Request $req) {
    // Hack to set client_id and other params required to
    // issue an access token
    // Ideally I'd like to do something like issueForUserId... But alas!!!
    $req->request->set('client_id', 'id');
    $req->request->set('client_secret', 'secret');
    $req->request->set('grant_type', 'user');

    $github = Socialite::driver('github');

    $github->stateless();
    $githubUser = $github->user();

    $user = App\User::firstOrNew([
      'email' => $githubUser->email,
    ]);

    if (!$user->exists) {
      $user->name = $githubUser->name;
      $user->password = str_random(16);
      $user->save();
    }

    Auth::login($user);

    return Response::json(Authorizer::issueAccessToken());
});
