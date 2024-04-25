# tda_to_schwab
This is a port/adaptation of the work of [Alex Reed](https://github.com/areed1192) over to Schwab's version of the TDA Idividual Trader API.

From here (https://github.com/areed1192/td-ameritrade-python-api) 
"The unofficial Python API client library for TD Ameritrade allows individuals with TD Ameritrade accounts to manage trades, pull historical and real-time data, manage their accounts, create and modify orders all using the Python programming language."

and here (https://github.com/areed1192/python-trading-robot) 
"A trading robot written in Python that can run automated strategies using a technical analysis. The robot is designed to mimic a few common scenarios".

Needless to say, it's a work in progress. There's lots of debug logging in client.py

Schwab made many changes, some noteworthy ones:

From Schwab's docs:
"Account numbers in plain text cannot be used outside of headers or request/response bodies. As the first step consumers must invoke [/accounts/accountNumbers] to retrieve the list of plain text/encrypted value pairs, and use encrypted account values for all subsequent calls for any accountNumber request."

Currently the refresh token expires in 7 days instead of 90, and with NO PROVISION to programmatically renew it. A new one can only be had through the oauth workflow. This is confirmed by TraderAPI@Schwab.com. Selenium/playwright/etc? 

The client_id (the "app_key"), is now only used in the initial (or subsequent) oauth workflow. After that, access token renewal calls use a base64 encoded string combination of APP KEY(client_id) and client_secret from the Schwab developer "app" registration in the header as {"Authorization": f"Basic {self.base64_client_id}}.

All other api endpoint calls use headers = {"Authorization": f"Bearer {self.state['access_token'] }"}. The client_id is not used in request parameters as was in the TDA API.

Most if not all endpoint URLs are changed.

The Orders and Transaction endpoints now "require" date ranges, unlike TDA. They must be in the format yyyy-MM-dd'T'HH:mm:ss.SSSZ.

I have noticed one response schema change from TDA's in /quotes, it's likely there are others. That's not relevant here but expect it.

Not all of the endpoints of the TDA API are in the Schwab API yet. (If ever?) "Saved Orders", "Watchlist", some of the "User Preference" ones to name some.

All of the function snippets in "tests_schwab_api.py" work as-is, but you must have a Schwab brokerage account number to test them. There's no sandbox for the Trader API - Individual yet, if there ever will be.

These endpoints still need review:

/chains

/expirationchain
