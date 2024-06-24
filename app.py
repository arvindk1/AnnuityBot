import os
import json
import time
from decimal import Decimal
import streamlit as st
import uuid
import boto3
from botocore.exceptions import ClientError

# Set page config at the very beginning
st.set_page_config(page_title="Annuity Master Bot", page_icon=None, layout="wide")

# Constants
TARGET_ACCOUNT_ID = '992382592107'
ROLE_NAME = 'OrganizationAccountAccessRole'
AGENT_ID = 'QYMNPZVEUJ'
AGENT_ALIAS_ID = 'EHRB95AFLH'

# Function to get AWS credentials
def get_aws_credentials():
    try:
        return {
            'aws_access_key_id': st.secrets["AWS_ACCESS_KEY_ID"],
            'aws_secret_access_key': st.secrets["AWS_SECRET_ACCESS_KEY"],
            'aws_session_token': st.secrets.get("AWS_SESSION_TOKEN"),
            'region_name': st.secrets.get("AWS_REGION", "us-east-1")
        }
    except KeyError:
        return {
            'aws_access_key_id': os.environ.get('AWS_ACCESS_KEY_ID'),
            'aws_secret_access_key': os.environ.get('AWS_SECRET_ACCESS_KEY'),
            'aws_session_token': os.environ.get('AWS_SESSION_TOKEN'),
            'region_name': os.environ.get('AWS_REGION', 'us-east-1')
        }

# Function to assume role in the target account
def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='BedrockAgentSession'
        )
        st.sidebar.success(f"Successfully assumed role in account {account_id}")
        st.sidebar.write(f"Temporary credentials expire at: {response['Credentials']['Expiration']}")
        return response['Credentials']
    except ClientError as e:
        st.error(f"Error assuming role: {e}")
        st.error(f"Error Code: {e.response['Error']['Code']}")
        st.error(f"Error Message: {e.response['Error']['Message']}")
        if 'ResponseMetadata' in e.response:
            st.error(f"Request ID: {e.response['ResponseMetadata'].get('RequestId')}")
        return None
    except Exception as e:
        st.error(f"Unexpected error assuming role: {str(e)}")
        return None

# Function to initialize session state
def init_state():
    if 'session_id' not in st.session_state:
        st.session_state.session_id = str(uuid.uuid4())
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    if 'citations' not in st.session_state:
        st.session_state.citations = []
    if 'trace' not in st.session_state:
        st.session_state.trace = {}

# Function to log conversations
def log(prompt, response, agent_id, agent_alias_id):
    try:
        table = dynamodb.Table('prompt_log')
        seconds = time.time()
        table.put_item(
            Item={
                'prompt': prompt,
                'response': response,
                'agent_id': agent_id,
                'agent_alias_id': agent_alias_id,
                'time': Decimal(str(seconds)),
            }
        )
        st.sidebar.success("Successfully logged conversation")
    except ClientError as e:
        st.sidebar.error(f"Failed to log conversation: {str(e)}")

# Function to list agents
def list_agents():
    try:
        response = bedrock_client.list_agents()
        st.write("Available Agents:")
        for agent in response.get('agentSummaries', []):
            st.write(f"Agent ID: {agent['agentId']}, Name: {agent['agentName']}")
        
        # List aliases for each agent
        for agent in response.get('agentSummaries', []):
            try:
                alias_response = bedrock_client.list_agent_aliases(agentId=agent['agentId'])
                st.write(f"Aliases for Agent {agent['agentName']}:")
                for alias in alias_response.get('agentAliasSummaries', []):
                    st.write(f"  Alias ID: {alias['agentAliasId']}, Name: {alias['agentAliasName']}")
            except ClientError as e:
                st.write(f"  Unable to list aliases for this agent: {e}")
    except ClientError as e:
        st.error(f"Error listing agents: {e}")
    except Exception as e:
        st.error(f"Unexpected error listing agents: {str(e)}")

# Initialize session state
init_state()

# Set up AWS session using credentials and assume role
try:
    # First, create a session with the current credentials
    session = boto3.Session(**get_aws_credentials())

    # Assume role in the target account
    credentials = assume_role(TARGET_ACCOUNT_ID, ROLE_NAME)

    if credentials:
        # Create a new session with the assumed role credentials
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=get_aws_credentials()['region_name']
        )

        # Test the session
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()["Account"]
        st.sidebar.success(f"Connected to AWS Account: {account_id}")

        # Create AWS clients
        dynamodb = session.resource('dynamodb')
        bedrock_agent_runtime_client = session.client('bedrock-agent-runtime')
        bedrock_client = session.client('bedrock')
    else:
        st.error("Failed to assume role in the target account.")
        st.stop()

except Exception as e:
    st.sidebar.error(f"Error setting up AWS session: {str(e)}")
    st.sidebar.error("Please ensure your AWS credentials are correctly set in environment variables or Streamlit secrets.")
    st.stop()

# Main app title
st.title("Annuity Master Bot")

# Sidebar buttons
with st.sidebar:
    if st.button("Reset Session"):
        st.session_state.messages = []
        st.session_state.citations = []
        st.session_state.trace = {}
        st.session_state.session_id = str(uuid.uuid4())
    if st.button("List Agents"):
        list_agents()

# Messages in the conversation
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"], unsafe_allow_html=True)

# Chat input that invokes the agent
if prompt := st.chat_input():
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.write(prompt)

    with st.chat_message("assistant"):
        placeholder = st.empty()
        placeholder.markdown("...")
        try:
            response = bedrock_agent_runtime_client.invoke_agent(
                agentId=AGENT_ID,
                agentAliasId=AGENT_ALIAS_ID,
                sessionId=st.session_state.session_id,
                inputText=prompt
            )

            # Read the response content
            output_text = ""
            for event in response['completion']:
                if 'chunk' in event:
                    chunk = event['chunk']
                    if 'bytes' in chunk:
                        output_text += chunk['bytes'].decode('utf-8')

            # Add citations
            if "citations" in response and len(response["citations"]) > 0:
                citation_num = 1
                num_citation_chars = 0
                citation_locs = ""
                for citation in response["citations"]:
                    end_span = citation["generatedResponsePart"]["textResponsePart"]["span"]["end"] + 1
                    for retrieved_ref in citation["retrievedReferences"]:
                        citation_marker = f"[{citation_num}]"
                        output_text = output_text[:end_span + num_citation_chars] + citation_marker + output_text[end_span + num_citation_chars:]
                        citation_locs = citation_locs + "\n<br>" + citation_marker + " " + retrieved_ref["location"]["s3Location"]["uri"]
                        citation_num += 1
                        num_citation_chars += len(citation_marker)
                    output_text = output_text[:end_span + num_citation_chars] + "\n" + output_text[end_span + num_citation_chars:]
                    num_citation_chars += 1
                output_text = output_text + "\n" + citation_locs

            placeholder.markdown(output_text, unsafe_allow_html=True)
            st.session_state.messages.append({"role": "assistant", "content": output_text})
            st.session_state.citations = response.get("citations", [])
            st.session_state.trace = response.get("trace", {})
            log(prompt, output_text, AGENT_ID, AGENT_ALIAS_ID)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            st.error(f"AWS Error: {error_code} - {error_message}")
            if error_code == 'ResourceNotFoundException':
                st.error("The specified agent or alias was not found. Please check your agent ID and alias ID.")
        except Exception as e:
            st.error(f"An unexpected error occurred: {str(e)}")
            print(f"Detailed error: {repr(e)}")  # This will print more details about the error

# Sidebar section for trace
with st.sidebar:
    st.title("Trace")

    trace_type_headers = {
        "preProcessingTrace": "Pre-Processing",
        "orchestrationTrace": "Orchestration",
        "postProcessingTrace": "Post-Processing"
    }
    trace_info_types = ["invocationInput", "modelInvocationInput", "modelInvocationOutput", "observation", "rationale"]

    # Show each trace types in separate sections
    step_num = 1
    for trace_type in trace_type_headers:
        st.subheader(trace_type_headers[trace_type])

        # Organize traces by step similar to how it is shown in the Bedrock console
        if trace_type in st.session_state.trace:
            trace_steps = {}
            for trace in st.session_state.trace[trace_type]:
                # Each trace type and step may have different information for the end-to-end flow
                for trace_info_type in trace_info_types:
                    if trace_info_type in trace:
                        trace_id = trace[trace_info_type]["traceId"]
                        if trace_id not in trace_steps:
                            trace_steps[trace_id] = [trace]
                        else:
                            trace_steps[trace_id].append(trace)
                        break

            # Show trace steps in JSON similar to the Bedrock console
            for trace_id in trace_steps.keys():
                with st.expander("Trace Step " + str(step_num), expanded=False):
                    for trace in trace_steps[trace_id]:
                        trace_str = json.dumps(trace, indent=2)
                        st.code(trace_str, language="json", line_numbers=trace_str.count("\n"))
                step_num += 1
        else:
            st.text("None")

    st.subheader("Citations")
    if len(st.session_state.citations) > 0:
        citation_num = 1
        for citation in st.session_state.citations:
            for retrieved_ref_num, retrieved_ref in enumerate(citation["retrievedReferences"]):
                with st.expander("Citation [" + str(citation_num) + "]", expanded=False):
                    citation_str = json.dumps({
                        "generatedResponsePart": citation["generatedResponsePart"],
                        "retrievedReference": citation["retrievedReferences"][retrieved_ref_num]
                    }, indent=2)
                    st.code(citation_str, language="json", line_numbers=citation_str.count("\n"))
                citation_num += 1
    else:
        st.text("None")
