from os import stat
from splunklib.client import connect

import click
import json
import os
import pandas as pd
import splunklib.client as client
import splunklib.results as results
import time
import warnings

BOLT_ESTIMATED_COMPRESSION: float = 0.3
CIM_QUERY: str = "| datamodel Network_Traffic All_Traffic search"


def load_config(json_fn: str) -> dict:
    with open(json_fn, "r") as f:
        return json.load(f)


def get_file_size(file_name: str) -> float:
    return stat(file_name).st_size


def get_size_on_disk(logs: list) -> float:
    tmp_file_name: str = "tmp.txt"
    with open(tmp_file_name, "w") as f:
        logs_text: str = "\n".join(logs)
        f.write(logs_text)
    file_size: float = get_file_size(tmp_file_name)
    os.remove(tmp_file_name)

    return file_size


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


def construct_query_args(earliest_time: str, latest_time: str, query_type: str) -> dict:
    if query_type == "event_count":
        search_args: dict = dict(exec_mode="normal")
    else:
        search_args: dict = dict(search_mode="normal")
    search_args["earliest_time"] = earliest_time
    search_args["latest_time"] = latest_time

    return search_args


def get_splunk_query_results(splunk_connection: client.Service, query: str, search_args: dict, verbose: bool):
    query_results: list = []

    job = splunk_connection.jobs.create(query, **search_args)
    if verbose:
        print("Querying Splunk results...")

    while not job.is_done():
        time.sleep(.2)

    count = 0
    # rr = results.ResultsReader(job.results(count=0))  # Max number of records in one poll 50k.
    rr = results.ResultsReader(splunk_connection.jobs.export(query, **search_args))
    for result in rr:
        if isinstance(result, dict):
            query_results.append(result["_raw"])
            count += 1

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


def get_largest_index(splunk_service: client.Service) -> str:
    index_info: dict = {}
    for index in splunk_service.indexes:
        index_info[index.name] = index["totalEventCount"]

    index_info_df: pd.DataFrame = (pd.DataFrame.from_dict(index_info, orient="index")
                                   .reset_index().set_axis(["name", "count"], axis=1)
                                   .astype({"count": int}))
    index_info_df.sort_values(by="count", axis=0, ascending=False, inplace=True)

    return index_info_df.iloc[0]["name"]


def get_index_info(splunk_service: client.Service, idx_name: str) -> dict:
    index_info: dict = {}
    for index in splunk_service.indexes:
        if index.name == idx_name:
            index_info["size"] = float(index["maxTotalDataSizeMB"])
            index_info["count"] = int(index["totalEventCount"])
            return index_info


def get_cim_compression_info(splunk_conn: client.Service, search_params: dict, verbose: bool) -> None:
    splunk_logs: list = get_splunk_query_results(splunk_conn, CIM_QUERY, search_params, verbose)
    input_size: float = get_size_on_disk(splunk_logs)
    input_size = round(input_size / (1024 * 1024))
    estimated_compressed_size: float = round(input_size * (1 - BOLT_ESTIMATED_COMPRESSION), 2)

    print(f"Found {len(splunk_logs)} events in the CIM datamodel whose size is "
          f"{input_size}MB. Estimated compressed size is {estimated_compressed_size}MB, "
          f"a reduction of {BOLT_ESTIMATED_COMPRESSION * 100.}%")


def get_index_compression_info(splunk_conn: client.Service, source_type: str, search_params: dict,
                               verbose: bool) -> None:
    warnings.warn("Found no events for CIM query. Perhaps CIM is not configured. If not specified, try providing a "
                  "start and end time for the query. Scanning the largest index instead...")

    collection_type: str = "index"
    selected_index: str
    selected_index_info: dict
    if source_type:
        splunk_query = f"search sourcetype={source_type} index=*"
        splunk_logs: list = get_splunk_query_results(splunk_conn, splunk_query, search_params, verbose)
        input_size: float = get_size_on_disk(splunk_logs)
        input_size = round(input_size / (1024 * 1024))
        selected_index = source_type
        selected_index_info = {"count": len(splunk_logs), "size": input_size}
        collection_type = "sourcetype"
    else:
        selected_index = get_largest_index(splunk_conn)
        selected_index_info = get_index_info(splunk_conn, selected_index)
    estimated_compressed_size: float = round(selected_index_info["size"] * (1 - BOLT_ESTIMATED_COMPRESSION), 2)

    print(f"The {collection_type} '{selected_index}' contains {selected_index_info['count']} records and is of size "
          f"{selected_index_info['size']}MB. Estimated compressed size is {estimated_compressed_size}MB, "
          f"a reduction of {BOLT_ESTIMATED_COMPRESSION * 100.}%.")


def query_firewall_datasource(splunk_conn: client.Service, event_count_params: dict, search_params: dict,
                              source_type: str, verbose: bool) -> None:
    total_event_count: int = get_event_count(splunk_conn, CIM_QUERY, event_count_params, verbose)
    if total_event_count > 0:
        get_cim_compression_info(splunk_conn, search_params, verbose)
    else:
        get_index_compression_info(splunk_conn, source_type, search_params, verbose)


def query_windows_datasource(splunk_conn: client.Service, event_count_params: dict,
                             source_type: str, verbose: bool) -> None:
    if source_type:
        windows_query: str = f"search sourcetype={source_type} index=*"
    else:
        windows_query: str = "search sourcetype=Wineventlog index=*"

    total_event_count: int = get_event_count(splunk_conn, windows_query, event_count_params, verbose)
    if total_event_count <= 0:
        print("No events found for the Windows datasource.")


def query_cloudwatch_datasource(splunk_conn: client.Service, event_count_params: dict,
                                source_type: str, verbose: bool) -> None:
    if source_type:
        cloudwatch_query: str = f"search sourcetype={source_type} index=*"
    else:
        cloudwatch_query: str = "search sourcetype=aws:cloudwatch index=*"

    total_event_count: int = get_event_count(splunk_conn, cloudwatch_query, event_count_params, verbose)
    if total_event_count <= 0:
        print("No events found for the Cloudwatch datasource.")


def splat(splunk_details: dict, source_category: str, source_type: str, start_time: str, end_time: str, verbose: bool):
    if not start_time:
        start_time = "-5m"
    if not end_time:
        end_time = "now"

    splunk_conn: client.Service = get_splunk_connection(splunk_details)
    search_params: dict = construct_query_args(start_time, end_time, query_type="search")
    event_count_params: dict = construct_query_args(start_time, end_time, query_type="event_count")

    if source_category == "firewall":
        query_firewall_datasource(splunk_conn, event_count_params, search_params, source_type, verbose)
    elif source_category == "windows":
        query_windows_datasource(splunk_conn, event_count_params, source_type, verbose)
    elif source_category == "cloudwatch":
        query_cloudwatch_datasource(splunk_conn, event_count_params, source_type, verbose)
    else:
        raise ValueError("Invalid source category specified. Exiting.")


@click.command()
@click.option("-sc", "--splunk-config", type=str, required=True, help="Path to JSON file specifying Splunk "
                                                                      "server configuration. Check GitHub "
                                                                      "README for details.")
@click.option("-sg", "--source-category", type=str, default="firewall", help="Source category which can be one"
                                                                             "of [firewall, windows, cloudwatch]")
@click.option("-sy", "--source-type", type=str, default="", help="Source type to query.")
@click.option("-st", "--start-time", default="", help=f"Query start time. It is specified in relation to the current"
                                                      f"time. So `-2d` means 2 days prior to now.")
@click.option("-et", "--end-time", default="", help=f"Query end time. It can either be `now` or a time in the past"
                                                    f"from the present like `-2d`.")
@click.option("-v", "--verbose", is_flag=True)
def main(splunk_config: str, source_category: str, source_type: str, start_time: str, end_time: str, verbose: bool):
    """Estimate compression of Splunk records achieved using Bolt.

    \b
    Examples:
        # Default case.
        splat --splunk-config splunk.json -v

        # For Windows sourcetype.
        splat --splunk-config splunk.json -sg windows -v

        # For AWS CloudWatch sourcetype
        splat --splunk-config splunk.json -sg cloudwatch -v

        # The default source types queried for various categories are as follows:
        # Firewall: None
        # Windows: Wineventlog
        # CloudWatch: aws:cloudwatch
        # We can specify a custom source type as well.
        splat --splunk-config splunk.json -sg firewall -sy <custom_sourcetype> -v

        # By default, data fetched from Splunk is for the past 5 minutes. We can also specify
        # custom start and end times.
        splat --splunk-config splunk.json --start-time 2020-11-10T12:00:00.000-00:00
        --end-time 2020-11-10T13:00:00.000-00:00
    """
    splunk_server_details = load_config(splunk_config)

    splat(splunk_server_details, source_category, source_type, start_time, end_time, verbose)


if __name__ == '__main__':
    main()
    # main(["-sc", "../splunk.json"])  # For debugging.
