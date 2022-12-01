<?php

# composer require google/cloud
# composer require google/apiclient

use App\Http\Controllers\Controller;
use Carbon\Carbon;
use Google\Cloud\RecaptchaEnterprise\V1\Assessment;
use Google\Cloud\RecaptchaEnterprise\V1\Event;
use Google\Cloud\RecaptchaEnterprise\V1\RecaptchaEnterpriseServiceClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Lang;
use Throwable;

class PostController extends Controller
{
    private RecaptchaEnterpriseServiceClient $captchaClient;

    private array $credentials;
    private string $sitekey;

    public function __construct()
    {
        # Create a service account from https://console.cloud.google.com/iam-admin/serviceaccounts?project=your_project_id_here
        # you will get a secret json file then you need put its content into this array
        $this->credentials = [
            'type' => 'fill_your_data_here',
            'project_id' => 'fill_your_data_here',
            'private_key_id' => 'fill_your_data_here',
            'private_key' => "fill_your_data_here",
            'client_email' => 'fill_your_data_here',
            'client_id' => 'fill_your_data_here',
            'auth_uri' => 'fill_your_data_here',
            'token_uri' => 'https://oauth2.googleapis.com/token',
            'auth_provider_x509_cert_url' => 'https://www.googleapis.com/oauth2/v1/certs',
            'client_x509_cert_url' => 'fill_your_data_here'
        ];
        $options = ['credentials' => $this->credentials, 'projectId' => $this->credentials['project_id'], 'keyFile' => 'fill_your_secret_json_path_here'];
        $this->sitekey = 'your_google_recaptcha_enterprise_sitekey';
        $this->captchaClient = new RecaptchaEnterpriseServiceClient($options);

        # Set the min and max action time (in seconds) of users since they fully loaded the page till they click submit button
        $this->min_action_time = 3;
        $this->max_action_time = 120;
    }

    # This function is to process your form post data through the protection of Google ReCaptcha Enterprise
    public function process(Request $request)
    {
        # Validate if has required input data
        $request->validate([
            'recaptcha_action' => 'string|required',
            'recaptcha_token' => 'string|required',
        ]);

        # Get Captcha result here
        try {
            # Init captcha client with recaptcha token rendered from users and bind to your Google project
            $event = (new Event())->setSiteKey($this->sitekey)->setToken($request->input('recaptcha_token'));
            $projectName = $this->captchaClient->projectName($this->credentials['project_id']);
            $assessment = (new Assessment())->setEvent($event);
            $response = $this->captchaClient->createAssessment($projectName, $assessment);
            if (! $response->getTokenProperties()->getValid()) {
                # some thing like return 'Captcha verification failed';
            } else {
                # You must set your action name in html frontend to verify if it matched to what users post to your backend
                # It seems like $request->validate
                $form_action = 'form/some_name_here';
                $action = $response->getTokenProperties()->getAction();

                # Migrated from Google ReCaptcha V3, the Enterprise captcha has Score too, and from 0.7 and up could be normal and good action
                $score = $response->getRiskAnalysis()->getScore();

                # Get which hostname requested to the Enterprise captcha on Google server, you should compare it to your domain name
                # This will help you prevent from Host File Redirection attack by download your render site to their local and edit etc/hosts to spam form to your site
                $hostname = $response->getTokenProperties()->getHostname();

                # Get and check if time action of users just like normal human, this is just my point, not from the Google documents
                # This will help you in the future if someone could solve Google Enterprise captcha like 2captcha or anti-captcha
                # But do not worry, it is impossible at least for now
                $time = $response->getTokenProperties()->getCreateTime()->getSeconds();
                $distance_time = Carbon::now()->diffInSeconds(gmdate("Y-m-d\TH:i:s\Z", $time));
                if (($distance_time < $this->min_action_time) || ($distance_time > $this->max_action_time)) {
                    # some thing like return 'Action too fast or too slow';
                }

                # Check if it matched action name, valid score and hostname
                if (($action !== $form_action) || ($score < 0.6) || (! str_contains($hostname, 'your_domain_here'))) {
                    # some thing like return 'Bot attack detected'
                }
            }
            # some thing like return 'Success passed captcha'
        } catch (Throwable $e) {
            # some thing like return $e->getMessage() if you want to debug
        }

        # some thing like return 'Success passed captcha'
    }
}
