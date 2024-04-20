# Adapted from the work of Alex Reed https://github.com/areed1192
#
# All the snippets in this file have been sucessfuly tested
# For those that require an account number,
# it must be Schwabs hash value for that account
#
from pyrobot.robot import PyRobot
from pprint import pprint
from configparser import ConfigParser

# Grab configuration values.
config = ConfigParser()
config.read("./config/config.ini")

#
CLIENT_ID = config.get("main", "CLIENT_ID")
CLIENT_SECRET = config.get("main", "CLIENT_SECRET")
REDIRECT_URI = config.get("main", "REDIRECT_URI")
CREDENTIALS_PATH = config.get("main", "JSON_PATH")
# Uncomment once you have a hash value to use:
# ACCOUNT_NUMBER = config.get("main", "ACCOUNT_NUMBER")

# Create a new session, credentials path is required.

trading_robot = PyRobot(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri=REDIRECT_URI,
    credentials_path=CREDENTIALS_PATH,
    # trading_account=ACCOUNT_NUMBER,
)

"""##########################
Get Account Number(s) hash value(s)
Returns ALL accounts for the logged in user

        Usage:
        trading_robot = PyRobot(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            redirect_uri=REDIRECT_URI,
            credentials_path=CREDENTIALS_PATH,
        )

        account_number_hash_values = list(trading_robot.session.get_account_number_hash_values())
        pprint(account_number_hash_values)
        print(f"First account number hash value: {account_number_hash_values[0]['hashValue']}")

"""

account_number_hash_values = list(
    trading_robot.session.get_account_number_hash_values()
)
pprint(account_number_hash_values)
print(f"First account number hash value: {account_number_hash_values[0]['hashValue']}")

"""##########################
Get accounts
Without account number, returns all linked accounts, with or without positions
"""

# account = trading_robot.session.get_accounts(
#     account="",
#     fields="positions",
# )
# pprint(account)

"""##########################
Get account, specific account, with or without positions
"""

# fields = "positions"
# account = trading_robot.session.get_accounts(
#     account=ACCOUNT_NUMBER,
#     fields=fields,
# )
# pprint(account)

"""##########################
Get orders

Works with or without an account number
Valid ISO-8601 format for times is : yyyy-MM-dd'T'HH:mm:ss.SSSZ
if to and from entered times are not given, defaults are "now", and "now - 60 days"
"""
# status = "FILLED"
# order = trading_robot.session.get_orders_path(
#     account=ACCOUNT_NUMBER,
#     # from_entered_time=from_entered_time,
#     # to_entered_time=to_entered_time,
#     status=status,
# )
# pprint(order)

"""##########################
Get orders

Without an account number, returns orders for all linked acounts
Valid ISO-8601 format for times is : yyyy-MM-dd'T'HH:mm:ss.SSSZ
if to and from entered times are not given, defaults are "now", and "now - 60 days"
"""

# status = "FILLED"
# order = trading_robot.session.get_orders_path(
#     #from_entered_time=from_entered_time,
#     # to_entered_time=to_entered_time,
#     status=status,
# )
# pprint(order)

"""##########################
Get specific order by order_id
"""

# order_id = 1000411469472
# order = trading_robot.session.get_order(
#     account=ACCOUNT_NUMBER,
#     order_id=order_id,
# )
# pprint(order)

"""##########################
Cancel order
"""

# order_id = 1000411469472
# order = trading_robot.session.cancel_order(account=ACCOUNT_NUMBER, order_id=order_id)
# pprint(order)

"""##########################
Get quote(s)
works with a single or multiple symbols 
fields can be quote, fundamental, extended, reference, regular, or 'empty'
indicative: default = False, see Schwab docs
"""

# stock = ["uvix", "C"]
# fields = []
# # indicative = True # default false
# quotes = trading_robot.session.get_quotes(
#     instruments=stock,
#     fields=fields,
#     # indicative=indicative
# )
# pprint(quotes)

"""##########################
Get Transactions

"""

# transaction_type = "TRADE"  # required
# transactions = trading_robot.session.get_transactions(
#     account=ACCOUNT_NUMBER,
#     # start_date,
#     # end_date="2024-03-27",
#     transaction_type=transaction_type,
#     # symbol="SQQQ",
# )
# pprint(transactions)

"""##########################
Get Transaction by id number
"""

# transaction_id = "80777088001"
# transactions = trading_robot.session.get_transactions(
#     account=ACCOUNT_NUMBER, transaction_id=transaction_id
# )
# pprint(transactions)

"""##########################
Get Preferences
"""

# preferences = trading_robot.session.get_preferences()
# pprint(preferences)

"""##########################
Search Instruments
Available projection values : symbol-search, symbol-regex, desc-search, desc-regex, search, fundamental default is "symbol-search".

"""
# symbol = "F"
# projection = "symbol-search"
# instrument = trading_robot.session.search_instruments(
#     symbol=symbol, projection=projection
# )
# pprint(instrument)

"""##########################
Get Instrument by cusip
"""

# cusip_id = "345370860"
# instrument_by_cusip = trading_robot.session.get_instruments(cusip_id)
# pprint(instrument_by_cusip)

"""##########################
Get Market Hours
"""

# markets = ["equity", "option"]  # equity, option, bond, future, forex
# date = "2024-04-19"  # Valid date range is from currentdate to 1 year from today. It will default to current day if not entered. Date format:YYYY-MM-DD
# hours = trading_robot.session.get_market_hours(markets=markets, date=date)
# pprint(hours)

"""##########################
Get Movers
"""

# symbol_id = "NYSE"  # Available values : $DJI, $COMPX, $SPX, NYSE, NASDAQ, OTCBB, INDEX_ALL, EQUITY_ALL, OPTION_ALL, OPTION_PUT, OPTION_CALL
# sort = "PERCENT_CHANGE_UP"  # Available values : VOLUME, TRADES, PERCENT_CHANGE_UP, PERCENT_CHANGE_DOWN
# frequency = 30  # Available values : 0, 1, 5, 10, 30, 60

# movers = trading_robot.session.get_movers(symbol_id, sort, frequency=frequency)
# pprint(movers)

"""##########################
Get price history 
"""

# symbol = "F"
# period_type = "day"
# """ Available values : day, month, year, ytd"""

# period = None
# """ For period type day - valid values are 1, 2, 3, 4, 5, 10 - if not specified defaults to 10
# For period type month - valid values are 1, 2, 3, 6 - if not specified defaults to 1
# For period type year - valid values are 1, 2, 3, 5, 10, 15, 20 - if not specified defaults to 1
# For period type ytd  valid value is 1 - if not specified defaults to 1
# """
# frequency_type = None
# """  # Available values : minute, daily, weekly, monthly
# If the periodType is day valid value is minute - if not specified defaults to minute
# If the periodType is month valid values are daily, weekly - if not specified defaults to weekly
# If the periodType is year valid values are daily, weekly, monthly - if not specified defaults to month
# If the periodType is ytd valid values are daily, weekly - if not specified defaults to weekly
# """
# frequency = None
# """ If the frequencyType is minute - valid values are 1, 5, 10, 15, 30 - If frequency is not specified, defaults to 1
# If the frequencyType is daily - valid value is 1 - If frequency is not specified, defaults to 1
# If the frequencyType is weekly - valid value is 1 - If frequency is not specified, defaults to 1
# If the frequencyType is monthly - valid value is 1 - If frequency is not specified, defaults to 1
# """
# start_date = None
# """ The start date, Time in milliseconds since the UNIX epoch eg 1451624400000
# If not specified, startDate will be (endDate - period) excluding weekends and holidays.
# """

# end_date = None
# """  The end date, Time in milliseconds since the UNIX epoch eg 1451624400000
# If not specified, the endDate will default to the market close of previous business day.
# """

# need_extended_hours_data = True
# need_previous_close = True

# history = trading_robot.session.get_price_history(
#     symbol=symbol,
#     period_type=period_type,
#     period=period,
#     frequency_type=frequency_type,
#     frequency=frequency,
#     start_date=start_date,
#     end_date=end_date,
#     need_extended_hours_data=need_extended_hours_data,
#     need_previous_close=need_previous_close,
# )

# pprint(history)
