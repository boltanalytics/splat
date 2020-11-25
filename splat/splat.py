from math import isnan
from os import stat
from splunklib.client import connect

import click
import json
import os
import pandas as pd
import re
import shlex
import splunklib.client as client
import splunklib.results as results
import time
import warnings


# command_line_args = {}
# logging.basicConfig(level=logging.INFO,
#                     format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
#                     datefmt='%Y-%m-%d %H:%M:%S',
#                     filename='/tmp/compression_estimator.log')


def read_logs(file_name: str) -> list:
    log_lines: list = []
    with open(file_name, "r") as f:
        file_contents: list = f.readlines()
    for line in file_contents:
        log_lines.append(line)

    return log_lines


def get_file_size(file_name: str) -> int:
    return stat(file_name).st_size


def convert_kv_to_string(kv_pairs: list) -> str:
    kv_str: list = []
    for kv_pair in kv_pairs:
        temp: list = []
        for k, v in kv_pair.items():
            if isinstance(v, str):
                temp.append(f"{k}={v}")
            elif (isinstance(v, (int, float))) and (not isnan(v)):
                temp.append(f"{k}={v}")

        kv_str.append(" ".join(temp))

    return "\n".join(kv_str)


def get_size_on_disk(kv_pairs: list) -> int:
    tmp_file_name: str = "tmp.txt"
    with open(tmp_file_name, "w") as f:
        kv_pairs_str: str = convert_kv_to_string(kv_pairs)
        f.write(kv_pairs_str)
    file_size: int = get_file_size(tmp_file_name)
    os.remove(tmp_file_name)

    return file_size


def get_key_value_pairs(text: list) -> list:
    key_value_pairs = []
    for line in text:
        kv_pairs: dict = {}
        for pair in shlex.split(line):
            if "=" in pair:
                kv_pair: list = pair.split("=")
                kv_pairs[kv_pair[0]] = kv_pair[1]
        key_value_pairs.append(kv_pairs)

    return key_value_pairs


def evaluate_ip_addr_freq(values: pd.Series, freq_thresh: float) -> bool:
    # Split IP addresses into 4 columns.
    ips_split: pd.DataFrame = values.str.split(".", expand=True)
    # Get the proportion of the most frequently occurring value in a column.
    ip_component_freq: pd.Series = ips_split.apply(lambda x: x.value_counts(normalize=True)[0], axis=0)
    return sum(ip_component_freq.values > freq_thresh) > 2


def evaluate_value_freq(values: pd.Series, freq_thresh: float) -> bool:
    # if pd.api.types.is_integer_dtype(values):
    #     return False
    # else:
    return round(values.value_counts(normalize=True)[0], 2) > freq_thresh


def is_ip_addr(x: str) -> bool:
    if not isinstance(x, str):
        return False
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", x))


def get_signif_keys_using_freq(kv_df: pd.DataFrame, freq_thresh: float) -> list:
    signif_keys = []
    for col_name in kv_df.columns:
        # Whether a column contains IP addresses is determined by only looking
        # at the first value.
        # if is_ip_addr(kv_df[col_name].iloc[0]):
        #     is_col_signif = evaluate_ip_addr_freq(kv_df[col_name], freq_thresh)
        # else:
        is_col_signif = evaluate_value_freq(kv_df[col_name], freq_thresh)

        if is_col_signif:
            signif_keys.append(col_name)

    return signif_keys


def convert_values_to_tokens(kv_df: pd.DataFrame, cols: list):
    for col in cols:
        kv_df.loc[:, col] = pd.factorize(kv_df[col])[0]
        # The `factorize` method converts NaNs to -1 which increases the size of output file.
        # Resetting -1's to None turns a series of type `int64` to `float64`. That is because
        # None values are represented by `numpy.nan` in a series. And `numpy.nan` is a float
        # value. So we convert the array to the type `arrays.IntegerArray` which is an
        # extension type implemented within Pandas.
        # https://pandas.pydata.org/pandas-docs/stable/user_guide/integer_na.html
        kv_df.loc[kv_df[col] == -1, col] = None
        if kv_df[col].dtype in ["float64"]:
            kv_df.loc[:, col] = kv_df[col].astype("Int64")

    return kv_df


def estimate_log_compression(log_kv_pairs: list, freq_threshold: float) -> dict:
    """
    Compute pre- and post-compression file size of an input list of key-value of pairs.

    :param log_kv_pairs: List of key-value pairs.
    :param freq_threshold: Minimum proportion required from the value of a key for the key to be converted to a
    template.
    :return: Dictionary containing size (in bytes) of input and compressed key-value pairs when written to a `.txt`
    file, percentage of compression achieved, and keys to use as templates.
    """
    input_size: int = get_size_on_disk(log_kv_pairs)
    log_kv_df: pd.DataFrame = pd.DataFrame(log_kv_pairs)

    keys_to_templatise: list = get_signif_keys_using_freq(log_kv_df, freq_threshold)
    log_kv_df: pd.DataFrame = convert_values_to_tokens(log_kv_df, keys_to_templatise)
    compressed_log_kv_pairs: list = log_kv_df.to_dict("records")

    output_size: int = get_size_on_disk(compressed_log_kv_pairs)
    percent_reduction: float = round((input_size - output_size) * 100 / input_size, 2)

    compression_info: dict = {
        "input_size": input_size,
        "output_size": output_size,
        "percent_reduction": percent_reduction,
        "keys_to_dedup": keys_to_templatise
    }

    return compression_info


def get_splunk_connection(splunk_config: dict) -> client.Service:
    service: client.Service = connect(
        host=splunk_config["host"],
        port=splunk_config["port"],
        username=splunk_config["username"],
        password=splunk_config["password"],
        owner=splunk_config["owner"],
        app=splunk_config["app"]
    )

    return service


def construct_search_args(earliest_time: str, latest_time: str) -> dict:
    search_args: dict = dict(exec_mode="normal")
    search_args["earliest_time"] = earliest_time
    search_args["latest_time"] = latest_time

    return search_args


def check_for_sufficient_data(event_count: int) -> None:
    if event_count <= 0:
        raise ValueError("There are no events for the given time. Please check input parameters such as "
                         "user credentials and query.")


def check_processing_time(event_count: int, verbose: bool, warning_thresh: int = 180) -> None:
    approx_processing_time = (event_count / 100000) * 10
    if verbose:
        print(f"Fetching {event_count} records from Splunk will require approximately "
              f"{approx_processing_time} minutes.")

    if approx_processing_time > warning_thresh:
        warnings.warn(f"Fetching {event_count} records from Splunk will require approximately "
                      f"{approx_processing_time} minutes. Faster but slightly less accurate results can be seen "
                      f"by reducing the query timespan")


def get_splunk_query_results(splunk_connection: client.Service, query: str, search_args: dict, n: int, verbose: bool):
    query_results: list = []

    if n > 0:
        query = f"{query} | head {n}"

    job = splunk_connection.jobs.create(query, **search_args)
    if verbose:
        print("Querying the splunk results...")

    while not job.is_done():
        time.sleep(.2)

    count = 0
    rr = results.ResultsReader(job.results(count=0))  # Max number of records in one poll 50k.
    for result in rr:
        if isinstance(result, dict):
            query_results.append(result["_raw"])
            count += 1
            if verbose:
                if count % 1000 == 0:
                    print(f"Retrieved {count} events so far and the current event is {result['_raw']}")

    assert rr.is_preview is False

    return query_results


def get_event_count(splunk_connection: client.Service, query: str, search_args: dict, verbose: bool) -> int:
    query = f"{query} | stats count as events_count"
    job = splunk_connection.jobs.create(query, **search_args)
    if verbose:
        print("Getting event count...")

    while not job.is_done():
        time.sleep(.2)

    rr = results.ResultsReader(job.results(count=0))  # Max number of records in one poll 50k.
    for result in rr:
        if isinstance(result, dict) and "events_count" in result:
            return int(result["events_count"])

    return 0


def splat(splunk_details: dict, index: str, start_time: str, end_time: str, num_records: int, verbose: bool):
    search_query: str = "search index={0}".format(index)
    splunk_conn: client.Service = get_splunk_connection(splunk_details)
    search_params: dict = construct_search_args(start_time, end_time)

    total_event_count: int = get_event_count(splunk_conn, search_query, search_params, verbose)
    check_for_sufficient_data(total_event_count)
    check_processing_time(total_event_count, verbose)

    splunk_logs: list = get_splunk_query_results(splunk_conn, search_query, search_params, num_records,
                                                 verbose)
    if verbose:
        print(f"Number of records retrieved from Splunk: {len(splunk_logs)}")

    log_key_value_pairs: list = get_key_value_pairs(splunk_logs)
    compression_stats: dict = estimate_log_compression(log_key_value_pairs, 0.9)

    print(f"Input data size: {round(compression_stats['input_size'] / 1024, 2)} KBs")
    print(f"Output data size: {round(compression_stats['output_size'] / 1024, 2)} KBs")
    print(f"Estimated compression: {compression_stats['percent_reduction']}%")


@click.command()
@click.option("-sc", "--splunk-config", type=str, required=True, help="Path to JSON file specifying Splunk "
                                                                      "server configuration. Check GitHub "
                                                                      "README for details.")
@click.option("-i", "--index", required=True, help="Splunk index to fetch results.")
@click.option("-st", "--start-time", required=True, help=f"Query start time. It is specified in relation to the current"
                                                         f"time. So `2d` means 2 days prior to now.")
@click.option("-et", "--end-time", required=True, help=f"Query end time. It can either be `now` or a time in the past"
                                                       f"from the present like `2d`.")
@click.option("-n", type=int, default=0, help="Number of records to limit the query to.")
@click.option("-v", "--verbose", is_flag=True)
def main(splunk_config: str, index: str, start_time: str, end_time: str, n: int, verbose: bool):
    """Estimate compression of Splunk records achieved by Bolt's <product_name>

    \b
    Examples:
        splat --splunk-config splunk.json --index firewall -n 5000 -v
        splat --splunk-config splunk.json --index firewall --start-time 2020-11-10T12:00:00.000-00:00 --end-time 2020-11-10T13:00:00.000-00:00
    """
    with open(splunk_config, "r") as f:
        splunk_server_details: dict = json.load(f)
    splat(splunk_server_details, index, start_time, end_time, n, verbose)


if __name__ == '__main__':
    main()
