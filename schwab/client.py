# Adapted from https://github.com/areed1192/td-ameritrade-python-api by Alex Reed
import datetime
import json
import logging
import pathlib
import base64
import time
import urllib.parse

from datetime import timedelta, timezone
from typing import Dict, List
import requests

from schwab.enums import VALID_CHART_VALUES
from schwab.exceptions import (
    ExdLmtError,
    ForbidError,
    GeneralError,
    NotFndError,
    NotNulError,
    ServerError,
    TknExpError,
)
from schwab.orders import Order


class SchwabClient:
    """Schwab API Client Class.

    Implements OAuth 2.0 Authorization Co-de Grant workflow, handles configuration
    and state management, adds token for authenticated calls, and performs request
    to the Schwab API.

    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        credentials_path: str,
        account_number: str = None,
        auth_flow: str = "default",
        _do_init: bool = True,
    ) -> None:
        """
        ### Usage:
        ----
            >>> # Credentials Path & Account Specified.
            >>> schwab_session = Schwab(
                client_id= '<CLIENT_ID>', (the "APP KEY" from Schwab)
                client_secret= '<CLIENT_SECRET>'
                redirect_uri='<REDIRECT_URI>',
                account_number='<ACCOUNT_NUMBER>',
                credentials_path='<CREDENTIALS_PATH>'
            )
            >>> schwab_session.login()
        """

        # Define the configuration settings.
        self.config = {
            "api_endpoint": "https://api.schwabapi.com",
            "auth_endpoint": "https://api.schwabapi.com/v1/oauth/authorize?",
            "token_endpoint": "https://api.schwabapi.com/v1/oauth/token",
            "refresh_enabled": True,
            "refresh_token_expires_in": 604800,  # 7 days
        }

        # Define the initalized state, these are the default values.
        self.state = {
            "access_token": None,
            "refresh_token": None,
        }

        self.auth_flow = auth_flow
        self.redirect_uri = redirect_uri
        self.account_number = account_number
        self.credentials_path = pathlib.Path(credentials_path)

        # define a new attribute called 'authstate' and initialize to `False`. This will be used by our login function.
        self.authstate = False

        # call the state_manager method and update the state to init (initalized)
        if _do_init:
            self._state_manager("init")

        # Initalize the client.
        self.client_id = client_id
        self.client_secret = client_secret
        self.base64_client_id = self._base64_client_id(
            self.client_id, self.client_secret
        )

        log_format = "%(asctime)-15s|%(filename)s|%(message)s"

        if not pathlib.Path("logs").exists():
            pathlib.Path("logs").mkdir()
            pathlib.Path("logs/client_test.log").touch()

        logging.basicConfig(
            filename="logs/client_test.log",
            level=logging.INFO,
            format=log_format,
        )

        self.request_session = requests.Session()
        self.request_session.verify = True

    def _state_manager(self, action: str) -> None:
        """Manages the session state.

        Manages the self.state dictionary. Initalize State will set
        the properties to their default value. Save will save the
        current state to file.

        ### Arguments:
        ----
        action {str}: action argument must of one of the following:
            'init' -- Initalize State.
            'save' -- Save the current state.
        """

        credentials_file_exists = self.credentials_path.exists()

        # If the file exists then load it.
        if action == "init" and credentials_file_exists:
            with open(file=self.credentials_path, mode="r") as json_file:
                self.state.update(json.load(json_file))

        # Saves the credentials file.
        elif action == "save":
            with open(file=self.credentials_path, mode="w+") as json_file:
                json.dump(obj=self.state, fp=json_file, indent=4)

    def login(self) -> bool:
        """Logs the user into the Broker API.

        Ask the user to authenticate  themselves via the Schwab Authentication Portal. This will
        create a URL, display it for the User to go to and request that they paste the final URL into
        command window. Once the user is authenticated the API key is valide for 90 days, so refresh
        tokens may be used from this point, up to the 90 days.

        ### Returns:
        ----
        {bool} -- Specifies whether it was successful or not.
        """

        # Only attempt silent SSO if the credential file exists.
        # only at login
        if (
            self.credentials_path.exists() and self._silent_sso()
        ):  # schwab_credentials exists and validate_tokens is True
            self.authstate = True
            return True
        else:
            # no credentials file or the refresh_token expired -> triggers the oauth flow
            self.oauth()
            self.authstate = True
            return True

    def logout(self) -> None:
        """Clears the current Broker Connection state."""
        # change state to initalized so they will have to either get a
        # new access token or refresh token next time they use the API
        self._state_manager("init")

    def __del__(self):
        # clear session
        if self.request_session:
            self.request_session.close()

    """
    -----------------------------------------------------------
    THIS BEGINS THE AUTH SECTION.
    -----------------------------------------------------------
    """

    def get_account_number_hash_values(self) -> List:
        endpoint = "trader/v1/accounts/accountNumbers"
        # make the request.
        return self._make_request(method="get", endpoint=endpoint)

    def grab_access_token(self) -> dict:
        # called by validate_tokens (the access_token is expired)
        """Refreshes the current access token.

        This takes a valid refresh token and refreshes
        an expired access token. This is different from
        exchanging a code for an access token.

        Returns:
        ----
        dict or None: The token dictionary if successful, None otherwise.
        """
        try:
            # Build the parameters of the request
            data = {
                "grant_type": "refresh_token",
                "refresh_token": self.state["refresh_token"],
            }
            # Make the request
            response = requests.post(
                url=self.config["token_endpoint"],
                headers=self._create_request_headers(is_access_token_request=True),
                data=data,
            )
            if response.ok:
                logging.info(f"Grab acces token resp: {response.json()}")
                return self._token_save(
                    token_dict=response.json(), refresh_token_from_oauth=False
                )
            else:
                # Log the error
                logging.error(
                    f"Failed to refresh access token. Status code: {response.status_code}, Reason: {response.text}"
                )
                if "expired" in response.text:
                    logging.info("oauth called from grab_access_token")
                    self.oauth()
        except requests.RequestException as e:
            # Log the exception
            logging.error(f"Failed to refresh access token: {e}")
            return None

    def oauth(self) -> None:
        # called by login(no credentials file) and validate_tokens (a token is expired) or _make_request if response not OK
        """Runs the oAuth process for the Broker API."""
        # Create the Auth URL.
        url = f"{self.config['auth_endpoint']}client_id={self.client_id}&redirect_uri={self.redirect_uri}"

        print(f"Please go to URL provided to authorize your account: {url}")
        # Paste it back and send it to exchange_code_for_token.
        redirect_url = input("Paste the full URL redirect here: ")

        logging.info(f"redirect_url: {redirect_url}")
        self.code = self._extract_redirect_code(redirect_url)
        logging.info(f"self.code: {self.code}")

        # Exchange the Auth Code for an Access Token.
        self.exchange_code_for_token()

    def exchange_code_for_token(self):
        # called by oauth
        """Access token handler for AuthCode Workflow.
        This takes the authorization code parsed from
        the auth endpoint to call the token endpoint
        and obtain an access token.

        ### Returns: {bool} -- `True` if successful, `False` otherwise.
        """
        url_code = self.code  # ?
        # Define the parameters of our access token post.
        data = {
            "grant_type": "authorization_code",
            "code": url_code,
            "redirect_uri": self.redirect_uri,
        }
        logging.info(f"data = {data}")
        # Make the request.
        response = requests.post(
            url=self.config["token_endpoint"],
            headers=self._create_request_headers(
                mode="form", is_access_token_request=True
            ),
            data=data,
        )

        if response.ok:
            logging.info(f"Exchange code for token resp: {response.json()}")
            self._token_save(token_dict=response.json(), refresh_token_from_oauth=True)
            return True
        else:
            # Handle the case where the request fails
            logging.info(
                f"Exchange_code_for_token request failed {response.status_code}, {response.text}"
            )
            return False

    def validate_tokens(self) -> bool:
        # called by _silent_sso at first login and  each _make_request
        # this function is only checking for token expiration times, nothing else
        """
        ### Returns
        -------
        bool
            Returns `True` if the tokens are not expired, `False` if
            they are.
        """

        if (
            "refresh_token_expires_at" in self.state
            and "access_token_expires_at" in self.state
        ):
            # should be true if _token_save already ran as part of oauth flow

            # Grab the refresh_token expire Time.
            refresh_token_exp = self.state["refresh_token_expires_at"]
            refresh_token_ts = datetime.datetime.fromtimestamp(refresh_token_exp)
            # Grab the Expire Threshold
            refresh_token_exp_threshold = refresh_token_ts - timedelta(days=1)
            # Convert Thresholds to Seconds.
            refresh_token_exp_threshold = refresh_token_exp_threshold.timestamp()
            # Check the Refresh Token first, is expired or expiring soon?
            logging.info(
                f"The refresh token will expire at: {self.state['refresh_token_expires_at_date']}"
            )
            if datetime.datetime.now().timestamp() > refresh_token_exp_threshold:
                self.oauth()
            # Grab the access_token expire Time.
            access_token_exp = self.state["access_token_expires_at"]
            access_token_ts = datetime.datetime.fromtimestamp(access_token_exp)
            # Grab the Expire Thresholds.
            access_token_exp_threshold = access_token_ts - timedelta(minutes=5)
            # Convert Thresholds to Seconds.
            access_token_exp_threshold = access_token_exp_threshold.timestamp()
            # See if we need a new Access Token.
            if datetime.datetime.now().timestamp() > access_token_exp_threshold:
                print("Grabbing new access token...")
                self.grab_access_token()
            return True
        else:
            # token expire times are not in self.state
            self.oauth()

    def _silent_sso(self) -> bool:
        # called by login
        # just returns bool from validate_tokens, just checks expirations
        """
        Overview:
        ----
        Attempt a silent authentication, by checking whether current
        access token has expired yet and/or attempting to refresh it. Returns
        True if we have successfully stored a valid access token.

        ### Returns:
        ----
        {bool} -- Specifies whether it was successful or not.
        """
        return self.validate_tokens()

    def _token_save(
        self, token_dict: dict, refresh_token_from_oauth: bool = False
    ) -> dict:  # called by grab_access_token and exchange_code_for_token
        """Parses the token and saves it.
        Overview:
        ----
        Parses an access token from the response of a POST request and saves it
        in the state dictionary for future use. Additionally, it will store the
        expiration time and the refresh token.

        Arguments:
        ----
        token_dict {dict} -- A response object received from the `exchange_code_for_token` or
            `grab_access_token` methods.

        Returns:
        ----
        {dict} -- A token dictionary with the new added values.
        """

        # Calculate access_token expiration times
        access_token_expire = time.time() + int(token_dict["expires_in"])
        access_token_expires_at_date = datetime.datetime.fromtimestamp(
            access_token_expire
        ).isoformat()

        # Prepare data to update the state, Save everything returned even if we're not using it.
        # saves refresh_token everytime whether it's new or not
        state_updates = {
            "expires_in": token_dict["expires_in"],
            "token_type": token_dict["token_type"],
            "scope": token_dict["scope"],
            "access_token": token_dict["access_token"],
            "access_token_expires_at": access_token_expire,
            "access_token_expires_at_date": access_token_expires_at_date,
            "id_token": token_dict["id_token"],
            "refresh_token": token_dict["refresh_token"],
        }

        # Update refresh_token & expiration data if necessary (we came here from oauth)
        if refresh_token_from_oauth:
            refresh_token_expire = time.time() + int(
                self.config["refresh_token_expires_in"]
            )
            state_updates.update(
                {
                    "refresh_token": token_dict["refresh_token"],
                    "refresh_token_expires_at": refresh_token_expire,
                    "refresh_token_expires_at_date": datetime.datetime.fromtimestamp(
                        refresh_token_expire
                    ).isoformat(),
                }
            )

        # Update state
        self.state.update(state_updates)

        # Save state
        self._state_manager("save")

        return self.state

    """
    -----------------------------------------------------------
    THIS BEGINS THE ACCOUNTS ENDPOINTS PORTION.
    -----------------------------------------------------------
    """

    def _api_endpoint(self, endpoint: str) -> str:
        # called by _make_request
        """Convert relative endpoint to full API endpoint."""
        return f"{self.config['api_endpoint']}/{endpoint}"

    def _create_request_headers(
        self, mode: str | None = None, is_access_token_request: bool = False
    ) -> dict:  # called by _make_request, grab_access_token, exchange_code_for_token
        """Create the headers for a request.

        Returns a dictionary of default HTTP headers for calls to the broker API,
        in the headers we defined the Authorization and access token.

        ### Arguments:
        ----
        is_access_token_request {bool}. Are the headers for an oauth request? default:False
        mode {str} -- Defines the content-type for the headers dictionary. (default: {None})

        ### Returns:
        ----
        {dict} -- Dictionary with the Access token and content-type
            if specified
        """
        if is_access_token_request:
            return {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {self.base64_client_id}",
            }

        else:
            headers = {"Authorization": f"Bearer {self.state['access_token'] }"}

            if mode == "json":
                headers["Content-Type"] = "application/json"
            elif mode == "form":
                headers["Content-Type"] = "application/x-www-form-urlencoded"

        return headers

    def _make_request(
        self,
        method: str,
        endpoint: str,
        mode: str | None = None,
        params: dict | None = None,
        data: dict | None = None,
        json: dict | None = None,
        order_details: bool = False,
    ) -> dict:
        url = self._api_endpoint(endpoint=endpoint)
        # Make sure the token is valid if it's not a Token API call.
        self.validate_tokens()
        headers = self._create_request_headers(mode=mode)

        # logging.info(f"Request URL: {url}")
        # logging.info(f"the headers: {headers}")
        # logging.info(f"the params: {params}")

        # Re-use session.
        request_session = self.request_session or requests.Session()
        # request_session = self.request_session

        # Define a new request.
        request_request = requests.Request(
            method=method.upper(),
            headers=headers,
            url=url,
            params=params,
            data=data,
            json=json,
        ).prepare()
        # Send the request.
        response = request_session.send(request=request_request, timeout=15)
        # grab the status code
        status_code = response.status_code

        if not response.ok:
            logging.error(f"make_requests error = {response.text}")
            if "refresh" in response.text and "expired" in response.text:
                # already passed validate_tokens for expirations so calculated time must be off...?
                try:
                    logging.error("oauth called from _make_request")
                    self.oauth()
                except Exception as e:
                    raise GeneralError(message=response.text) from e
            else:
                if response.status_code == 400:
                    raise NotNulError(message=response.text)
                elif response.status_code == 401:
                    raise TknExpError(message=response.text)
                elif response.status_code == 403:
                    raise ForbidError(message=response.text)
                elif response.status_code == 404:
                    raise NotFndError(message=response.text)
                elif response.status_code == 429:
                    raise ExdLmtError(message=response.text)
                elif response.status_code == 500 or response.status_code == 503:
                    raise ServerError(message=response.text)
                elif response.status_code > 400:
                    raise GeneralError(message=response.text)
        else:  # Then response is OK
            response_headers = response.headers
            # Grab the order id, if it exists.
            if "Location" in response_headers:
                order_id = response_headers["Location"].split("orders/")[1]
            else:
                order_id = ""

            # Return response data
            if order_details:
                return {
                    "order_id": order_id,
                    "headers": response.headers,
                    "content": response.content,
                    "status_code": status_code,
                    "request_body": request_request.body,
                    "request_method": request_request.method,
                }
            else:
                return response.json()

    def _prepare_arguments_list(self, parameter_list: List[str]) -> str:
        """
        Prepares a list of parameter values for certain API calls.

        Some endpoints accept multiple values for a parameter. This method takes a list
        of parameter values and creates a comma-separated string that can be used in an API request.

        Arguments:
        ----
        parameter_list: A list of parameter values assigned to an argument.

        Usage:
        ----
            >>> schwab_client._prepare_arguments_list(['MSFT', 'SQ'])
        """

        # Ensure parameter_list is not None and is a list
        if parameter_list is None:
            raise ValueError("Parameter list cannot be None")
        if not isinstance(parameter_list, list):
            raise TypeError("Parameter list must be a list")

        return ",".join(parameter_list)

    def get_quotes(
        self,
        instruments: List[str],
        fields: List[str] | None = None,
        indicative: bool = False,
    ) -> Dict:
        """
        Get quotes for specified instruments.
        Works for a single instrument or multiple
        Arguments:
        ----
        instruments {List[str]} -- List of instrument symbols.

        fields {Optional[List[str]]} -- List of fields to include in the quotes (default: None).
        Request for subset of data by passing coma separated list of root nodes,
        possible root nodes are:
        quote, fundamental, extended, reference, regular.
        Sending quote, fundamental in request will return quote and fundamental data in response.
        Dont send this attribute for full response.

        indicative:bool=False -- Include indicative symbol quotes for all ETF symbols in request.
        If ETF symbol ABC is in request and indicative=true API will return
        quotes for ABC and its corresponding indicative quote for $ABC.IV
        Available values : true, false


        Returns:
        ----
        {Dict} -- Dictionary containing the quotes data.
        """
        # Prepare instruments list for the request.
        instruments = self._prepare_arguments_list(parameter_list=instruments)

        # Prepare fields list if provided.
        if fields:
            fields = self._prepare_arguments_list(parameter_list=fields)

        # Build the params dictionary.
        params = {"symbols": instruments}
        if fields:
            params["fields"] = fields
        params["indicative"] = indicative

        # Define the endpoint.
        endpoint = "marketdata/v1/quotes"

        # Return the response of the get request.
        return self._make_request(method="get", endpoint=endpoint, params=params)

    def get_orders_path(
        self,
        account: str | None = None,
        max_results: int | None = None,
        from_entered_time: str | None = None,
        to_entered_time: str | None = None,
        status: str | None = None,
    ) -> Dict:
        """
        Returns all the orders for a specific account, or all orders for all linked accounts if no account is specified.

        Arguments:
        ----
        account: The account number that you want to query for orders. Leave out for all linked accounts

        Keyword Arguments:
        ----
        max_results: The maximum number of orders to retrieve.
        from_entered_time: Specifies the start time to query for orders. Default is 10 days ago.
        to_entered_time: Specifies the end time to query for orders. Default is current time.
        status: Specifies the status of orders to be returned.

        Usage:
        ----
            >>> schwab_client.get_orders_path(
                account='MyAccountID',
                max_results=6,
                from_entered_time='yyyy-MM-ddTHH:mm:ss.SSSZ',
                to_entered_time='yyyy-MM-ddTHH:mm:ss.SSSZ',
                status='FILLED'
            )
        """
        # Set default values for from_entered_time and to_entered_time if not provided
        # Mimics TDA legacy API which did not 'require' these parameters
        if not to_entered_time:
            to_entered_time = self._utcformat(datetime.datetime.now())

        if not from_entered_time:
            from_entered_time = self._utcformat(
                datetime.datetime.now() - timedelta(days=60)
            )

        # Define the payload
        params = {
            "maxResults": max_results,
            "fromEnteredTime": from_entered_time,
            "toEnteredTime": to_entered_time,
            "status": status,
        }

        # Define the endpoint

        endpoint = (
            "trader/v1/orders"
            if not account
            else f"trader/v1/accounts/{account}/orders"
        )  # All linked accounts or specific account

        # Make the request
        return self._make_request(method="get", endpoint=endpoint, params=params)

    def get_order(self, account: str, order_id: str) -> Dict:
        """
        Returns a specific order for a specific account.

        Arguments:
        ----
        account {str} -- The account number that you want to query orders for.

        Keyword Arguments:
        ----
        order_id {str} -- The ID of the order you want to retrieve.

        Usage:
        ----
            >>> schwab_client.get_orders(account='MyAccountID', order_id='MyOrderID')

        Returns:
        ----
        {Dict} -- A response dictionary.
        """

        # Define the endpoint
        endpoint = f"trader/v1/accounts/{account}/orders/{order_id}"
        # Make the request
        return self._make_request(method="get", endpoint=endpoint)

    def get_accounts(
        self, account: str | None = None, fields: str | None = None
    ) -> Dict:
        """
        Queries accounts for a user.

        Serves as the mechanism to make a request to the "Get Accounts" and "Get Account" Endpoint.
        If one account is provided, a "Get Account" request will be made. If more than one account
        is provided, then a "Get Accounts" request will be made.

        Arguments:
        ----
        account {Optional[str]} -- The account number you wish to receive data on.
                                    Default value is None, which will return all accounts of the user.

        fields {Optional[str]} -- Schwab accepts only "positions" here.

        Usage:
        ----
                >>> schwab_client.get_accounts(
                    account='MyAccountNumber',
                    fields='positions'
                )
        """
        # Schwab accepts only "positions" here.
        # Build the params dictionary.
        params = {"fields": fields} if fields else None

        # Determine the endpoint based on the provided account.
        endpoint = (
            "trader/v1/accounts" if not account else f"trader/v1/accounts/{account}"
        )

        # Return the response of the get request.
        return self._make_request(method="get", endpoint=endpoint, params=params)

    def cancel_order(self, account: str, order_id: str) -> Dict:
        """
        Cancel a specific order for a specific account.

        Arguments:
        ----
        account {str} -- The account number for which the order was made.
        order_id {str} -- The ID of the order to be cancelled.

        Usage:
        ----
            >>> schwab_client.cancel_order(account='MyAccountID', order_id='MyOrderID')

        Returns:
        ----
        {Dict} -- A response dictionary.
        """

        # define the endpoint
        endpoint = f"trader/v1/accounts/{account}/orders/{order_id}"

        # make the request
        return self._make_request(
            method="delete", endpoint=endpoint, order_details=True
        )

    def place_order(self, account: str, order: Dict) -> Dict:
        """
        Places an order for a specific account.

        Arguments:
        ----
        account {str} -- The account number for which the order should be placed.

        order {Dict} -- The order payload.

        Usage:
        ----
            >>> schwab_client.place_order(account='MyAccountID', order={'orderKey': 'OrderValue'})

        Returns:
        ----
        {Dict} -- A response dictionary.
        """

        # Check if the order is an instance of Order class, and extract order details if so
        if isinstance(order, Order):
            order = order._grab_order()

        return self._make_request(
            method="post",
            endpoint=f"trader/v1/accounts/{account}/orders",
            mode="json",
            json=order,
            order_details=True,
        )

    def modify_order(self, account: str, order: Dict, order_id: str) -> Dict:
        """
        Modifies an existing order.
        Arguments:
        ----
        account {str} -- The account number for which the order was placed.

        order {Dict} -- The new order payload.

        order_id {str} -- The ID of the existing order.

        Usage:
        ----
            >>> schwab_client.modify_order(account='MyAccountID', order={'orderKey': 'OrderValue'}, order_id='MyOrderID')

        Returns:
        ----
        {Dict} -- A response dictionary.
        """

        # Check if the order is an instance of Order class, and extract order details if so
        if isinstance(order, Order):
            order = order._grab_order()

        # Make the request
        endpoint = f"trader/v1/accounts/{account}/orders/{order_id}"
        return self._make_request(
            method="put", endpoint=endpoint, mode="json", json=order, order_details=True
        )

    def get_transactions(
        self,
        account: str,
        transaction_type: str | None = None,
        symbol: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        transaction_id: str | None = None,
    ) -> Dict:
        """Queries the transactions for an account.

        Serves as the mechanism to make a request to the "Get Transactions" and "Get Transaction" Endpoint.
        If one `transaction_id` is provided a "Get Transaction" request will be made and if it is not provided
        then a "Get Transactions" request will be made.

        ### Documentation:
        ----

        ### Arguments:
        ----

        account {str} -- Required -- The account number you wish to recieve
        transactions for.

        transaction_id: If transaction_id, no other args apply. The transaction ID you wish to search. If this is
            specifed a "Get Transaction" request is made. Should only be
            used if you wish to return one transaction, (a known transaction_id number)

        transaction_type: The type of transaction. Only
            transactions with the specified type will be returned.
            Valid values are the following: see below

        symbol The symbol in the specified transaction. Only transactions
            with the specified symbol will be returned.

        start_date: Only transactions after the Start Date will be returned.
            Note: The maximum date range is one year. Valid ISO-8601
            formats are: yyyy-MM-dd'T'HH:mm:ss.SSSZ

        end_date: Only transactions before the End Date will be returned.
            Note: The maximum date range is one year. Valid ISO-8601
            formats are: yyyy-MM-dd'T'HH:mm:ss.SSSZ

        ### Usage:
        ----
            >>> schwab_client.get_transactions(account = 'MyAccountNumber', transaction_type = '[]', start_date = 'yyyy-MM-dd'T'HH:mm:ss.SSSZ', end_date = 'yyyy-MM-dd'T'HH:mm:ss.SSSZ')
            >>> schwab_client.get_transactions(account = 'MyAccountNumber', transaction_type = 'TRADE' start_date = 'yyyy-MM-dd'T'HH:mm:ss.SSSZ', end_date = 'yyyy-MM-dd'T'HH:mm:ss.SSSZ')
            >>> schwab_client.get_transactions(transaction_id = 'MyTransactionID')

        """
        # Set default values for start_date and end_date if not provided
        # Mimics TDA legacy API which did not 'require' these parameters
        if not start_date:
            start_date = self._utcformat(datetime.datetime.now() - timedelta(days=60))
            # print(start_date)
        else:
            pass  # make sure it's within 60 days from now
        if not end_date:
            end_date = self._utcformat(datetime.datetime.now())
            # print(end_date)

        # default to a "Get Transaction" Request if anything else is passed through along with the transaction_id.
        if transaction_id is not None:
            account = account
            transaction_type = (None,)
            start_date = (None,)
            end_date = None

        # if the request type they made isn't valid print an error and return nothing.
        else:
            if transaction_type not in [
                "TRADE",
                "RECEIVE_AND_DELIVER",
                "DIVIDEND_OR_INTEREST",
                "ACH_RECEIPT",
                "ACH_DISBURSEMENT",
                "CASH_RECEIPT",
                "CASH_DISBURSEMENT",
                "ELECTRONIC_FUND",
                "WIRE_OUT",
                "WIRE_IN",
                "JOURNAL",
                "MEMORANDUM",
                "MARGIN_CALL",
                " MONEY_MARKET",
                "SMA_ADJUSTMENT",
            ]:
                print("The type of transaction type you specified is not valid.")
                raise ValueError("Bad Input")

        # if transaction_id is not none, it means we need to make a request to the get_transaction endpoint.
        if transaction_id:
            # define the endpoint
            endpoint = f"trader/v1/accounts/{account}/transactions/{transaction_id}"

            # return the response of the get request.
            return self._make_request(method="get", endpoint=endpoint)

        # if it isn't then we need to make a request to the get_transactions endpoint.
        else:
            # build the params dictionary
            params = {
                "types": transaction_type,
                "symbol": symbol,
                "startDate": start_date,
                "endDate": end_date,
            }
            print(f"get transaction params: {params}")
            if account is None and self.account_number:
                account = self.account_number

            # define the endpoint
            endpoint = f"trader/v1/accounts/{account}/transactions"

            # return the response of the get request.
            return self._make_request(method="get", endpoint=endpoint, params=params)

    def get_preferences(self) -> Dict:
        """Get's User Preferences for a specific account.
        ### Documentation:
        ----
        ### Arguments:
        ----
        None. Get user preference information for the logged in user.
        ### Usage:
        ----
            >>> schwab_client.get_preferences()
        ### Returns:
        ----
            Perferences dictionary
        """
        # define the endpoint
        endpoint = "trader/v1//userPreference"
        # return the response of the get request.
        return self._make_request(method="get", endpoint=endpoint)

    def search_instruments(self, symbol: str, projection: str | None = None) -> Dict:
        """Search or retrieve instrument data, including fundamental data.

        ### Documentation:
        ----
        ### Arguments:
        ----
        symbol: The symbol of the financial instrument you would
            like to search.

        projection: The type of request,
        Available values : symbol-search, symbol-regex, desc-search, desc-regex, search, fundamental default is "symbol-search".
                1. symbol-search
                Retrieve instrument data of a specific symbol or cusip

            2. symbol-regex
                Retrieve instrument data for all symbols matching regex.
                Example: symbol=XYZ.* will return all symbols beginning with XYZ

            3. desc-search
                Retrieve instrument data for instruments whose description contains
                the word supplied. Example: symbol=FakeCompany will return all
                instruments with FakeCompany in the description

            4. desc-regex
                Search description with full regex support. Example: symbol=XYZ.[A-C]
                returns all instruments whose descriptions contain a word beginning
                with XYZ followed by a character A through C

            5. search


            6 fundamental

                Returns fundamental data for a single instrument specified by exact symbol.

        ### Usage:
        ----
            >>> schwab_client.search_instrument(
                    symbol='XYZ',
                    projection='symbol-search'
                )
            >>> schwab_client.search_instrument(
                    symbol='XYZ.*',
                    projection='symbol-regex'
                )
            >>> schwab_client.search_instrument(
                    symbol='FakeCompany',
                    projection='desc-search'
                )
            >>> schwab_client.search_instrument(
                    symbol='XYZ.[A-C]',
                    projection='desc-regex'
                )
            >>> schwab_client.search_instrument(
                    symbol='XYZ.[A-C]',
                    projection='fundamental'
                )
        """

        # build the params dictionary
        params = {"symbol": symbol, "projection": projection}

        # define the endpoint
        endpoint = "marketdata/v1/instruments"

        # return the response of the get request.
        return self._make_request(method="get", endpoint=endpoint, params=params)

    def get_instruments(self, cusip_id: str) -> Dict:
        """Searches an Instrument.

        Get an instrument by CUSIP (Committee on Uniform Securities Identification Procedures) code.

        ### Documentation:
        ----
        ht-tps://developer.tdamer-itrade.com/instruments/apis/get/instruments/%7Bcusip%7D

        ### Arguments:
        ----
        cusip: The CUSIP co-de of a given financial instrument.

        ### Usage:
        ----
            >>> schwab_client.get_instruments(
                cusip='SomeCUSIPNumber'
            )
        """

        # define the endpoint
        endpoint = f"marketdata/v1/instruments/{cusip_id}"

        # return the response of the get request.
        return self._make_request(method="get", endpoint=endpoint)

    def get_market_hours(self, markets: List[str], date: str | None = None) -> Dict:
        """Returns the hours for a specific market.

        Serves as the mechanism to make a request to the "Get Hours for Multiple Markets" and
        "Get Hours for Single Markets" Endpoint. If one market is provided a "Get Hours for Single Markets"
        request will be made and if more than one item is provided then a "Get Hours for Multiple Markets"
        request will be made.

        ### Documentation:
        ----
        ### Arguments:
        ----
        markets: The markets for which you're requesting market hours,
            comma-separated. Valid markets are:
            EQUITY, OPTION, FUTURE, BOND, or FOREX.

        date: Valid date range is from current date to 1 year from today.
        It will default to current day if not entered. Date format:YYYY-MM-DD

        ### Usage:
        ----
            >>> schwab_client.get_market_hours(markets=['EQUITY'], date='2019-10-19')
            >>> schwab_client.get_market_hours(markets=['EQUITY','FOREX'], date='2019-10-19')
        """

        # because we have a list argument, prep it for the request.
        markets = self._prepare_arguments_list(parameter_list=markets)

        # build the params dictionary
        params = {"markets": markets, "date": date}

        # define the endpoint
        endpoint = "marketdata/v1/markets"

        # return the response of the get request.
        return self._make_request(method="get", endpoint=endpoint, params=params)

    def get_movers(
        self, symbol_id: str, sort: str | None = None, frequency: int | None = None
    ) -> Dict:
        """Gets Active movers for a specific Index.

        Top 10 (up or down) movers by value or percent for a particular market.

        ### Documentation:
        ----
        ### Arguments:
        ----
        symbol_id:
        Available values : $DJI, $COMPX, $SPX, NYSE, NASDAQ, OTCBB,
        INDEX_ALL, EQUITY_ALL, OPTION_ALL, OPTION_PUT, OPTION_CALL

        sort: Sort by a particular attribute
        Available values : VOLUME, TRADES, PERCENT_CHANGE_UP, PERCENT_CHANGE_DOWN

        frequency: To return movers with the specified directions of up or down
        Available values : 0, 1, 5, 10, 30, 60

        ### Usage:
        ----
            >>> schwab_client.get_movers(
                    symbol_id='$DJI',
                    sort ='PERCENT_CHANGE_UP',
                    frquency = 10
                )
            >>> schwab_client.get_movers(
                    symbol_id='$COMPX',
                    sort='VOLUME',
                    change='percent'
                )
        """

        # build the params dictionary
        params = {"sort": sort, "frequency": frequency}

        # define the endpoint
        endpoint = f"marketdata/v1/movers/{symbol_id}"

        # return the response of the get request.
        return self._make_request(method="get", endpoint=endpoint, params=params)

    def get_price_history(
        self,
        symbol: str,
        period_type: str | None = None,
        period: int | None = None,
        frequency_type: str | None = None,
        frequency: int | None = None,
        start_date: int | None = None,
        end_date: int | None = None,
        need_extended_hours_data: bool = True,
        need_previous_close: bool = True,
    ) -> Dict:
        """Gets historical candle data for a financial instrument.

        ### Arguments:
        ----
        symbol:str The ticker symbol to request data for.

        period_type:str The type of period to show.
            Valid values are day, month, year, or
            ytd (year to date). Default is day.

        period:int The number of periods to show.
        If the periodType is
        • day - valid values are 1, 2, 3, 4, 5, 10
        • month - valid values are 1, 2, 3, 6
        • year - valid values are 1, 2, 3, 5, 10, 15, 20
        • ytd - valid values are 1

        If the period is not specified and the periodType is
        • day - default period is 10.
        • month - default period is 1.
        • year - default period is 1.
        • ytd - default period is 1.

        start_date:int Start date as milliseconds
            since epoch.
        If not specified startDate will be (endDate - period) excluding weekends and holidays.

        end_date:int End date as milliseconds
            since epoch.
        If not specified, the endDate will default to the market close of previous business day.

        frequency_type:str The time frequencyType

        The type of frequency with
        which a new candle is formed.
        Available values : minute, daily, weekly, monthly
        If the periodType is
        • day - valid value is minute
        • month - valid values are daily, weekly
        • year - valid values are daily, weekly, monthly
        • ytd - valid values are daily, weekly

        If frequencyType is not specified, default value depends on the periodType
        • day - defaulted to minute.
        • month - defaulted to weekly.
        • year - defaulted to monthly.
        • ytd - defaulted to weekly.


        frequency:int The number of the frequency type
            to be included in each candle.
        The time frequency duration

        If the frequencyType is
        • minute - valid values are 1, 5, 10, 15, 30
        • daily - valid value is 1
        • weekly - valid value is 1
        • monthly - valid value is 1

        If frequency is not specified, default value is 1

        needExtendedHoursData:bool -> Need extended hours data?
        extended_hours: True to return extended hours
            data, false for regular market hours only.
            Default is true

        needPreviousClose:bool -> Need previous close price/date?

        """

        # Fail early, can't have a period with start and end date specified.
        if start_date and end_date and period:
            raise ValueError("Cannot have Period with start date and end date")

        # Check only if you don't have a date and do have a period.
        elif not start_date and not end_date and period:
            # Attempt to grab the key, if it fails we know there is an error.
            # check if the period is valid.
            if int(period) in VALID_CHART_VALUES[frequency_type][period_type]:
                True
            else:
                raise IndexError("Invalid Period.")

            if frequency_type == "minute" and int(frequency) not in [1, 5, 10, 15, 30]:
                raise ValueError("Invalid Minute Frequency, must be 1,5,10,15,30")

        # build the params dictionary
        params = {
            "symbol": symbol,
            "periodType": period_type,
            "period": period,
            "startDate": start_date,
            "endDate": end_date,
            "frequency": frequency,
            "frequencyType": frequency_type,
            "needExtendedHoursData": need_extended_hours_data,
            "needPreviousClose": need_previous_close,
        }

        # define the endpoint
        endpoint = "marketdata/v1/pricehistory"

        # return the response of the get request.
        return self._make_request(method="get", endpoint=endpoint, params=params)

    """
    -----------------------------------------------------------
    MISC
    -----------------------------------------------------------
    """

    def _utcformat(self, dt, timespec="milliseconds"):
        """
        Convert datetime to string in UTC format (YYYY-mm-ddTHH:MM:SS.mmmZ)
        Like Schwab wants.
        This is needed for   /accounts/{accountNumber}/orders,  /orders, and /accounts/{accountNumber}/transactions
        """
        iso_str = dt.astimezone(timezone.utc).isoformat("T", timespec)
        if iso_str.endswith("+00:00"):
            iso_str = iso_str[:-6] + "Z"  # Replace the last 6 characters with "Z"
        return iso_str

    def _base64_client_id(self, client_id: str, client_secret: str):
        """
        Encode client credentials (client_id:client_secret) using Base64 encoding.
        Args:
            client_id (str): The Client ID.
            client_secret (str): The Client Secret.

        Returns:
            str: The Base64 encoded string of client_id:client_secret used in the header of access token requests
        """

        try:
            api_credentials = f"{client_id}:{client_secret}"
            encoded_credentials = base64.b64encode(
                api_credentials.encode("utf-8")
            ).decode("utf-8")
            return encoded_credentials
        except Exception as e:
            # Log encoding errors
            logging.error(f"Error encoding client credentials: {e}")
            return ""

    def _extract_redirect_code(self, redirect_url: str) -> str:
        if "code=" in redirect_url and "&session=" in redirect_url:
            try:
                start_index = redirect_url.index("code=") + len("code=")
                end_index = redirect_url.index("&session=")
                # Extract substring between "code=" and "&session="
                extracted_text = redirect_url[start_index:end_index]
                # URL decode the extracted text
                extracted_code = urllib.parse.unquote(extracted_text)
                return extracted_code
            except ValueError as ve:
                logging.error(f"There's a problem with the redirect url 'code' {ve}")
        else:
            logging.error(
                f"There's a problem with the redirect url 'code' {redirect_url}"
            )
            return ""
