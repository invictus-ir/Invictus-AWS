Get started
===========

To run the script you will have to use the AWS CLI.

* Install the AWS CLI package. You can simply follow the instructions here : https://aws.amazon.com/cli/.
* Install Python3 on your local system
* Install the requirements with :samp:`pip3 install -r requirements.txt`
* An account with permissions to access the AWS environment you want to acquire data from
* Configure AWS account with :samp:`aws configure`

.. note::

    Note: This requires the AWS Access Key ID for the account you use to run the script.

The user running the script must have these 2 policies in order to have the necessary permissions :

* The AWS managed - job function policy :samp:`ReadOnlyAccess`
* The policy that you can find in :samp:`source/files/policy.json`
