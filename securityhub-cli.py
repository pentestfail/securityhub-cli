#!/usr/bin/env python

import argparse
import boto3
import datetime
import json
import logging
import os
import sys
import pandas as pd
import time
from pivottablejs import pivot_ui
from botocore.exceptions import ClientError


######################################
# GLOBAL VARIABLES
######################################

version = '0.0.2'
ctime = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime())

# Argument validators
Comparison = ['EQUALS', 'PREFIX', 'NOT_EQUALS', 'PREFIX_NOT_EQUALS']
ComplianceStatus = ['FAILED', 'PASS', 'NOT_AVAILABLE', 'WARNING']
LogLevels = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']
RecordState = ['ACTIVE', 'ARCHIVED']
SeverityLabel =  [ 'INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
WorkflowStatus = ['NEW', 'NOTIFIED', 'SUPPRESSED', 'RESOVLVED']
SortCriteria = ['asc', 'desc']

# Field search/filter types
# ComparisonsField = []
CidrField = ['ResourceAwsEc2InstanceIpV4Addresses', 'ResourceAwsEc2InstanceIpV6Addresses', 'NetworkSourceIpV4', 'NetworkSourceIpV6', 'NetworkDestinationIpV4', 'NetworkDestinationIpV6']
DateField = ['CreatedAt', 'FirstObservedAt', 'LastObservedAt', 'ThreatIntelIndicatorLastObservedAt', 'UpdatedAt']

# Types Taxonomy - https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-type-taxonomy.html
Types_Prefixes = [
	'Effects/',
	'Sensitive Data Identifications/',
	'Software and Configuration Checks/',
	'Software and Configuration Checks/Vulnerabilities/',
	'Software and Configuration Checks/AWS Security Best Practices/',
	'Software and Configuration Checks/Industry and Regulatory Standards/',
	'TTPs/',
	'Unusual Behaviors/'
]

# Default lists & objects used for execution
finding_filter = {}
findings_list = []
finding_sortcriteria = [{'Field': 'UpdatedAt', 'SortOrder': 'asc'}]
# meta_fields used for flattening API response and formatting dataframe for export to CSV, Excel, etc.
meta_fields = ["Action","AwsAccountId","Compliance","Confidence","CreatedAt","Criticality","Description","FirstObservedAt","GeneratorId","Id","LastObservedAt","Malware","Network","NetworkPath","Note","PatchSummary","Process","ProductArn","ProductFields","RecordState","RelatedFindings","SourceUrl","ThreatIntelIndicators","Title","Types","UpdatedAt","UserDefinedFields","VerificationState","Vulnerabilities","Workflow","WorkflowState",["Severity","Product"],["Severity","Label"],["Severity","Normalized"],["Severity","Original"],["Remediation","Recommendation","Text"],["Remediation","Recommendation","Url"],["ProductFields","StandardsArn"],["ProductFields","StandardsSubscriptionArn"],["ProductFields","ControlId"],["ProductFields","RecommendationUrl"],["ProductFields","RelatedAWSResources:0/name"],["ProductFields","RelatedAWSResources:0/type"],["ProductFields","StandardsControlArn"],["ProductFields","aws/securityhub/ProductName"],["ProductFields","aws/securityhub/CompanyName"],["ProductFields","aws/securityhub/FindingId"],["Compliance","Status"],["Workflow","Status"],["ProductFields","aws/securityhub/annotation"],["ProductFields","StandardsGuideArn"],["ProductFields","StandardsGuideSubscriptionArn"],["ProductFields","RuleId"],["Compliance","StatusReasons"]]


######################################
# ARGUMENT PARSING CLASSES
######################################

# Create a keyvalue action class to parse key=value pairs in arguments
class keyvalue(argparse.Action):
	# Constructor calling 
	def __call__( self , parser, namespace, values, option_string = None): 
		finding_filter[self.dest] = []
		  
		for value in values: 
			# split it into key and value 
			key, value = value.split('=') 
			# assign into dictionary 
			finding_filter[self.dest].append({'Key': key, 'Value': value, 'Comparison': 'EQUALS'})

# Create class to create simple value comparisons
class valuecomp(argparse.Action):
	# Constructor calling 
	def __call__( self , parser, namespace, values, option_string = None): 
		finding_filter[self.dest] = []
		
		for value in values:
			# assign into dictionary
			finding_filter[self.dest].append({'Value': value, 'Comparison': 'EQUALS'})

# Create class to create simple value comparisons
class valuecopy(argparse.Action):
	# Constructor calling 
	def __call__( self , parser, namespace, values, option_string = None):		 
		for value in values:
			finding_filter[self.dest] = value

# Create class to create simple value comparisons
class valuecidr(argparse.Action):
	# Constructor calling 
	def __call__( self , parser, namespace, values, option_string = None):		 
		finding_filter[self.dest] = []

		for value in values:
			# assign into dictionary
			finding_filter[self.dest].append({'Cidr': value})

class sort_criteria(argparse.Action):
	# Constructor calling 
	def __call__( self , parser, namespace, values, option_string = None):
		setattr(namespace, self.dest, {'Field': values[0], 'SortOrder': values[1]})


######################################
# FUNCTIONS
######################################

def get_tags_dict(tags):
    # Reformats list of AWS tags dictionaries into single dictionary
    # INPUT: [{'key': 'AppVersion', 'value': 'ami-xxx'}, ...]
    # OUTPUT: {'AppVersion': 'ami-xxx', ...}
    new_tags = {}
    for x in tags:
        new_tags[x['key']] = x.get('value')
    return new_tags

def datetime_handler(x):
	# Function to handle AWS API responses w/ datetime objects
	if isinstance(x, datetime.datetime):
		return x.isoformat()
	raise TypeError("Unknown type")

def get_sechub_members(region):
	# Gets all SecurityHub members of specified region 
	sechub_client = boto3.client('securityhub', region_name=region)
	next_token = ''
	accounts_list = []

	while next_token is not None:
		accounts_enabled = sechub_client.list_members(OnlyAssociated=True, MaxResults=50, NextToken=next_token)
		next_token = accounts_enabled.get('NextToken', None)
		# current_batch = accounts_enabled['Members']

		for member in accounts_enabled['Members']:
			accounts_list.append(member['AccountId'])

	return accounts_list

def get_sechub_findings(region, finding_filter, sort=None):
	session = boto3.session.Session()
	sechub_client = session.client('securityhub', region_name=region)
	# next_token = ''  # variable to hold the pagination token
	findings_region_list = []

	# while next_token is not None:
	finding_pages = sechub_client.get_paginator('get_findings')
	finding_page = finding_pages.paginate(Filters=finding_filter, SortCriteria=sort, PaginationConfig={'PageSize': 100})
		# next_token = finding_results.get('NextToken', None)

	for page in finding_page:
		for finding in page['Findings']:
			findings_region_list.append(finding)
		
	return findings_region_list

def filter_resource(finding_filter, region, member_accounts, InstanceId):
	# "ResourceId":[{"Comparison":"EQUALS","Value":"arn:aws:ec2:us-east-1:292051043935:instance/i-0d1e66f5f60a0d0fc"}]
	finding_filter['ResourceId'] = []
	
	logging.debug('REGION={0:s} MEMBERS={1}'.format(region, json.dumps(member_accounts, default=datetime_handler)))

	for member in member_accounts:
		finding_filter['ResourceId'].append({"Comparison":"EQUALS","Value":"arn:aws:ec2:{0}:{1}:instance/{2}".format(region, member, InstanceId)})

def get_findings(finding_filter, findings_list, regions, args):
	# Check for globally used filters
	if args['DateField']:
		finding_filter[args['DateField']] = []
		if args['DateRangeFixed']:
			# assign into dictionary 
			finding_filter[args['DateField']].append(
				{
					'Start': args['DateRangeFixed'][0],
					'End': args['DateRangeFixed'][1]
				}
			)
		elif args['DateRangeRelative']:
			# assign into dictionary
			finding_filter[args['DateField']].append(
				{
					'DateRange': {
						'Value': args['DateRangeRelative'],
						'Unit': 'DAYS'
					}
				}
			)
		else:
			logging.error('OH NO YOU KILLED KENNY!', str(namespace))

	# TODO - Investigate Keyword use and potential value
	# if args['Keyword']:
	# 	finding_filter['Keyword'] = []
	# 	for keyword in args['Keyword']:
	# 		finding_filter['Keyword'].append(
	# 			{'Value': keyword}
	# 		)

	logging.debug('SecurityHub Query INITIAL_FILTER={0}'.format(json.dumps(finding_filter)))

	# Logic to handle searching for resources using friendly names vs ARNs
	if args['InstanceIds']:
		# Alternate logic to iterate over regions per-each InstanceIds (supporting auto-stop, per-InstanceId vs region)
		return get_findings_instance(finding_filter, findings_list, regions, args)
	else:
		# Default logic to iterate over regions with same query (supporting auto-stop)
		return get_findings_regions(finding_filter, findings_list, regions, args)

def get_findings_regions(finding_filter, findings_list, regions, args):
	# Iterate query over regions found
	ir = 0 # Counts iterated regions for logging & status
	r = len(regions) # Number of regions to be queried for logging & status
	for region in regions:
		ir += 1 # Add to iterated regions count (ir of r regions)
		logging.info('Started ({0} of {1} REGIONS) SecurityHub query in REGION={2}'.format(ir, r, region))
		
		try:
			# DEBUG - Log the created filter query
			logging.debug('SecurityHub Query REGION={0} FILTER={1}'.format(region, json.dumps(finding_filter)))
			# Get findings region
			findings_region = get_sechub_findings(region, finding_filter, args['SortCriteria'])

			# Append findings_instance into findings_region
			for finding in findings_region:
				findings_list.append(finding)

		except Exception as error:
			logging.error(error)
			continue

		if len(findings_region)>0 and args['autostop']:
			logging.debug('Completed AUTO-STOP ENABLED REGION={0} ({1} of {2} REGIONS)'.format(region, ir, r))
			break
		else:
			logging.info('Completed REGION={2} ({0} of {1} REGIONS) REGIONAL_FINDINGS={3} TOTAL_FINDINGS={4}'.format(ir, r, region, len(findings_region), len(findings_list)))

	logging.info('Completed SecurityHub collection TOTAL_FINDINGS={0}'.format(len(findings_list)))
	return findings_list

def get_findings_instance(finding_filter, findings_list, regions, args):
	# Iterate over InstanceIds to prevent 20 filter query limit
	ii = 0 # Counts iterated InstanceId for logging & status
	i = len(args['InstanceIds']) # Number of InstanceId to be queried for logging & status
	for InstanceId in args['InstanceIds']:
		ii += 1 # Add to iterated InstanceId count (ii of i InstanceIds)
		findings_instance = []

		# Iterate query over regions found
		ir = 0 # Counts iterated regions for logging & status
		r = len(regions) # Number of regions to be queried for logging & status
		for region in regions:
			ir += 1 # Add to iterated regions count (ir of r regions)
			logging.info('Started INSTANCEID={0} ({1} of {2}) REGION={3} ({4} of {5})'.format(InstanceId, ii, i, region, ir, r))
			
			try:
				# Get list of SecurityHub member accounts to create resource query
				member_accounts = get_sechub_members(region)

				filter_resource(finding_filter, region, member_accounts, InstanceId)
				# DEBUG - Log the created filter query
				logging.debug('SecurityHub Query INSTANCEID={0} REGION={1} FILTER={2}'.format(InstanceId, region, json.dumps(finding_filter)))
				# Get findings per-InstanceId
				findings_region = get_sechub_findings(region, finding_filter, args['SortCriteria'])

				# Append findings_instance into findings_region
				for finding in findings_region:
					findings_instance.append(finding)
				
			except Exception as error:
				logging.error(error)
				continue

			if len(findings_instance)>0 and args['autostop']:
				logging.debug('Completed AUTO-STOP ENABLED INSTANCEID={0} ({1} of {2}) REGION={3}'.format(InstanceId, ii, i, region))
				break

		# Append regional findings into findings_list
		for finding in findings_instance:
			findings_list.append(finding)

		logging.info('Completed INSTANCEID={0} ({1} of {2}) INSTANCE_FINDINGS={3} TOTAL_FINDINGS={4}'.format(InstanceId, ii, i, len(findings_instance), len(findings_list)))

	logging.info('Completed SecurityHub collection TOTAL_FINDINGS={0}'.format(len(findings_list)))
	return findings_list

def get_query(findings_list, regions, args):
	# Validate the input querystring is a valid JSON object before submitting to SecurityHub
	if type(args['querystring']) is str:
		querystring = args['querystring']
		logging.debug('get_query STRING args.querystring={}'.format(querystring))
	elif type(args['querystring']) is list:
		querystring = ' '.join(args['querystring'])
		logging.debug('get_query LIST args.querystring={}'.format(querystring))
	else:
		raise TypeError('ERROR: get_query querystring type unknown!')

	try:
		finding_filter = json.loads(querystring)
		if args['showquery']:
			logging.info('SecurityHub Query FILTER={}'.format(finding_filter))
		logging.debug('QUERYSTRING={}'.format(json.dumps(querystring)))
	except Exception as error:
		raise error

	# Iterate query over regions found
	ir = 0 # Counts iterated regions for logging & status
	r = len(regions) # Number of regions to be queried for logging & status
	for region in regions:
		ir += 1 # Add to iterated regions count (i of r regions)
		logging.info('Started ({0} of {1} REGIONS) SecurityHub query in REGION={2}'.format(ir, r, region))

		try:
			# Query for findings in region
			findings_region = get_sechub_findings(region, finding_filter, args['SortCriteria'])
		except Exception as error:
			logging.error(error)
			continue

		# Append regional findings into findings_list
		for finding in findings_region:
			findings_list.append(finding)

		logging.info('Completed REGION={2} ({0} of {1} REGIONS) REGIONAL_FINDINGS={3} TOTAL_FINDINGS={4}'.format(ir, r, region, len(findings_region), len(findings_list)))

		if len(findings_list)>0 and args['autostop']:
			logging.debug('Completed AUTO-STOP ENABLED  REGION={0} ({1} of {2} REGIONS)'.format(region, ir, r))
			break

	logging.info('Completed SecurityHub collection TOTAL_FINDINGS={0}'.format(len(findings_list)))
	return findings_list

def get_findings_summary(findings_list, meta_fields=meta_fields):
    find = {'findings': findings_list}
    df = pd.DataFrame(find)
    dfn = pd.json_normalize(df['findings'], record_path=['Resources'], meta=meta_fields, record_prefix='Resource.', errors='ignore')
    print(pd.crosstab(dfn['Types'], dfn['Severity.Label'])) #.to_markdown()

def get_findings_csv(findings_list, output_filename=None, meta_fields=meta_fields):
	# Create dataframe and write CSV data
	find = {'findings': findings_list}
	df = pd.DataFrame(find)
	dfn = pd.json_normalize(df['findings'], record_path=['Resources'], meta=meta_fields, record_prefix='Resource.', errors='ignore')
	if output_filename is not None:
		output_filename = '{}.csv'.format(output_filename)
		dfn.to_csv(output_filename, index=False)
		logging.info('Completed writing to OUTPUTFILE={0} FORMAT=CSV'.format(output_filename))
	else:
		print(dfn.to_csv(index=False))

def get_findings_json(findings_list, output_filename=None):
	# Write output as JSON
	if output_filename is not None:
		output_filename = '{}.json'.format(output_filename)
		with open(output_filename, 'w') as f:
			f.write(json.dumps({"Findings": findings_list}, indent=2))
		f.close()
		logging.info('Completed writing to OUTPUTFILE={0} FORMAT=JSON'.format(output_filename))
	else:
		print(json.dumps({"Findings": findings_list}, indent=2))

def get_findings_jsonl(findings_list, output_filename=None):
	# Write output as JSON-Newline (JSONL)
	if output_filename is not None:
		output_filename = '{}.jsonl'.format(output_filename)
		with open(output_filename, 'w') as f:
			for finding in findings_list:
				f.write(str(json.dumps(finding)) + '\n')
		f.close()
		logging.info('Completed writing to OUTPUTFILE={0} FORMAT=JSON'.format(output_filename))
	else:
		for finding in findings_list:
			print(json.dumps(finding))

def get_findings_pivot(findings_list, output_filename=None, meta_fields=meta_fields):
	# Write output as HTML Pivot-table
	if output_filename is not None:
		output_filename = '{}.html'.format(output_filename)
		find = {'findings': findings_list}
		df = pd.DataFrame(find)
		dfn = pd.json_normalize(df['findings'], record_path=['Resources'], meta=meta_fields, record_prefix='Resource.', errors='ignore')
		pivot_ui(dfn, rows=['AwsAccountId','Resource.Region','Resource.Tags.Project','Resource.Tags.App','Resource.Id','Resource.Tags.Name'] , cols=['Severity.Label'], aggregatorName='Count', rendererName='Col Heatmap', outfile_path=output_filename)
		logging.info('Completed writing to OUTPUTFILE={0} FORMAT=PIVOT'.format(output_filename))
	else:
		logging.error('Unable to write OUTPUTFILE={0} FORMAT=PIVOT'.format(output_filename))

def get_findings_excel(findings_list, output_filename=None, meta_fields=meta_fields):
	# Create dataframe and write CSV data
	find = {'findings': findings_list}
	df = pd.DataFrame(find)
	dfn = pd.json_normalize(df['findings'], record_path=['Resources'], meta=meta_fields, record_prefix='Resource.', errors='ignore')
	if output_filename is not None:
		output_filename = '{}.xlsx'.format(output_filename)
		dfn.to_excel(output_filename, sheet_name='findings', merge_cells=False, index=False)
		logging.info('Completed writing to OUTPUTFILE={0} FORMAT=EXCEL'.format(output_filename))
	else:
		logging.error('Unable to write OUTPUTFILE={0} FORMAT=EXCEL'.format(output_filename))


######################################
# ARGUMENTS & PARAMETERS (argparse)
######################################

parent_parser = argparse.ArgumentParser(description="The parent parser", add_help=False, allow_abbrev=False)
parser = argparse.ArgumentParser(description='AWS SecurityHub CLI: A user-friendly command-line client to query AWS SecurityHub and export events or generate reports.', allow_abbrev=False)
parser.add_argument('-v', '--version', action='version', version=version)
subparsers = parser.add_subparsers(title='actions', help='sub-command help', dest='action', required=True)

# query = parser.add_subparsers(title='querystring', description='Accepts valid SecurityHub query as JSON.', help='Boto3 SecurityHub API get_findings() - https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html#SecurityHub.Client.get_findings')

# Add GLOBAL arguments to parse
parent_parser.add_argument('-a', '--autostop', help='Stop iterating regions once findings returned (DEFAULT: %(default)s).', action='store_true', default=False)
parent_parser.add_argument('--showquery', help='Show the query that is submitted to SecurityHub (DEFAULT: %(default)s).', action='store_true', default=False)
parent_parser.add_argument('-o', '--outputfile', help='Filename to write collected events.', const='DEFAULT', nargs='?', type=str, required=False)
parent_parser.add_argument('-f', '--format', help='Output format to write events into file [--filename] (DEFAULT: %(default)s).', choices=['JSON', 'JSONL', 'CSV', 'EXCEL', 'PIVOT', 'SUMMARY'], default='JSON', nargs='+', type=str, required=False)
parent_parser.add_argument('--loglevel', help='Modify logging verbosity (DEFAULT: %(default)s).', choices=LogLevels, type=str, required=False, default='INFO')
# parser.add_argument('--logfile', help='Filename to write log events.', type=str, required=False)
parent_parser.add_argument('-r', '--Regions', '--Region', help='AWS region(s) to query (DEFAULT: All returned from EC2 describe_regions() API.).', dest='Region', nargs='+', required=False)
parent_parser.add_argument('-s', '--SortCriteria', metavar=('Field', 'SortOrder'), help='Sort findings by a results field (e.g. SeverityLabel) and order (asc|desc) (DEFAULT: %(default)s).', dest='SortCriteria', nargs=2, action=sort_criteria, type=str, default=finding_sortcriteria, required=False)

# get_insights = subparsers.add_parser('get_insights', parents=[parent_parser], help='Query SecurityHub insights.')

# get_query > Query Filters
parser_get_query = subparsers.add_parser('get_query', parents=[parent_parser], help='Query SecurityHub findings by providing your own querystring (JSON querystring).')
parser_get_query.add_argument('querystring', help='Accepts valid SecurityHub query as JSON.', nargs='+')

# get-findings > Finding Filters
parser_get_findings = subparsers.add_parser('get_findings', parents=[parent_parser], help='Search SecurityHub findings using CLI filters. You can filter by up to 10 finding attributes. For each attribute, you can provide up to 20 filter values.')
filter_finding = parser_get_findings.add_argument_group('Finding Filters', 'Filter query by fields & values.')
filter_finding.add_argument('-i', '--InstanceIds', help="An EC2 InstanceId value to collect associated findings. (RECOMMENDATION: Enable --autostop)", nargs='+', required=False)
filter_finding.add_argument('--ComplianceStatus', help='Finding status result of a check run against a specific rule in a supported standard, such as CIS AWS Foundations (DEFAULT: %(default)s).', dest='ComplianceStatus', action=valuecomp, choices=RecordState, nargs='+', required=False, default=['FAILED', 'WARNING'])
filter_finding.add_argument('--ProductName', help='SecurityHub product name (e.g. Inspector, GuardDuty)', dest='ProductName', nargs='+', action=valuecomp, required=False)
# filter_finding.add_argument('-k', '--Keyword', help="A keyword for a finding.", nargs='+', required=False)
filter_finding.add_argument('--RecordState', help='One or more RecordState values (DEFAULT: %(default)s).', dest='RecordState', choices=RecordState, nargs='+', action=valuecomp, required=False, default='ACTIVE')
filter_finding.add_argument('--SeverityLabel', help='One or more SeverityLabel values.', dest='SeverityLabel', choices=SeverityLabel, nargs='+', action=valuecomp, required=False)
filter_finding.add_argument('-t', '--tags', help='List of AWS resource tags & values to query (FORMAT: tag=value).', dest='ResourceTags', nargs='+', action=keyvalue, required=False)
filter_finding.add_argument('--WorkflowStatus', dest='WorkflowStatus', choices=WorkflowStatus, nargs='+', action=valuecomp, required=False)

# get_findings > Date Filters
filter_date = parser_get_findings.add_argument_group('Date Filters', 'Filter query by timestamp fields.')
filter_date.add_argument('--DateField', help='Select a timestamp field to filter findings  (DEFAULT: %(default)s).', nargs='?', const='UpdatedAt', choices=DateField, required=False)
filter_date_ranges = filter_date.add_mutually_exclusive_group()
filter_date_ranges.add_argument('-dates', '--DateRangeFixed', metavar=('Start', 'End'), help='An ISO8601-formatted timestamps (required if --DateField specified).', nargs=2, type=str, required=False)
filter_date_ranges.add_argument('-days', '--DateRangeRelative', metavar='DAYS', help='Filter since DAYS ago (DEFAULT: %(default)s).', type=int, required=False, default=90)

# Parse namespace the arguments
args = vars(parser.parse_args())


######################################
# MAIN CODE
######################################

# Configure Logging
logging.basicConfig(
	format="{asctime} {levelname:<8} {message}",
	style="{",
	level=args['loglevel'],
	stream=sys.stderr,
)

logging.debug('ARGUMENTS={}'.format(json.dumps(args)))
logging.debug('INITIAL FINDING_FILTER={}'.format(json.dumps(finding_filter)))

# Get regions available to iterate
if args['Region'] is not None:
	regions = args['Region']
else:
	ec2_client = boto3.client('ec2') # Create EC2 Boto3 client
	regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
logging.debug('AWS Regions: {}'.format(regions)) # DEBUG log output of regions list

# Execute functions based on args['action'] argument
if args['action']=='get_findings':
	if args['showquery']:
		logging.info('SecurityHub Query FILTER={}'.format(json.dumps(finding_filter)))
	get_findings(finding_filter, findings_list, regions, args)
elif args['action']=='get_query':
	get_query(findings_list, regions, args)
else:
	logging.error('INVALID ACTION!')

# Format outputs & set default filename
if args['outputfile'] is None:
	outputfile = None
elif args['outputfile']=='DEFAULT':
	# Create reporting files folder
	os.makedirs('securityhub-reports', exist_ok=True)
	outputfile = 'securityhub-reports/securityhub-{}-{}'.format(args['action'], ctime)
else:
	outputfile = args['outputfile']

if 'JSON' in args['format']:
	try:
		get_findings_json(findings_list, outputfile)
	except Exception as json_error:
		logging.error('Failed to write JSON to OUTPUTFILE={0}.json REASON={1}'.format(outputfile, json_error))
		pass
if 'JSONL' in args['format']:
	try:
		get_findings_jsonl(findings_list, outputfile)
	except Exception as jsonl_error:
		logging.error('Failed to write JSONL to OUTPUTFILE={0}.jsonl REASON={1}'.format(outputfile, jsonl_error))
		pass
if 'CSV' in args['format']:
	try:
		get_findings_csv(findings_list, outputfile)
	except Exception as csv_error:
		logging.error('Failed to write CSV to OUTPUTFILE={0}.csv REASON={1}'.format(outputfile, csv_error))
		pass
if 'PIVOT' in args['format']:
	try:
		get_findings_pivot(findings_list, outputfile)
	except Exception as pivot_error:
		logging.error('Failed to write PIVOT to OUTPUTFILE={0}.html REASON={1}'.format(outputfile, pivot_error))
		pass
if 'EXCEL' in args['format']:
	try:
		get_findings_excel(findings_list, outputfile)
	except Exception as excel_error:
		logging.error('Failed to write EXCEL to OUTPUTFILE={0}.xlsx REASON={1}'.format(outputfile, excel_error))
		pass
if 'SUMMARY' in args['format']:
	# Currently not working on aggregated results
	# get_findings_summary(findings_list)
	pass
