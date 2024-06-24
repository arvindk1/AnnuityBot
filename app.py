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
# us-east-1
# AGENT_ID = 'QYMNPZVEUJ'
# AGENT_ALIAS_ID = 'EHRB95AFLH'

#us-west-2
AGENT_ID = 'KXWRFB462G'
AGENT_ALIAS_ID = 'CUDE7XPZVF'

# Function to get AWS credentials
def get_aws_credentials():
    try:
        return {
            'aws_access_key_id': st.secrets["AWS_ACCESS_KEY_ID"],
            'aws_secret_access_key': st.secrets["AWS_SECRET_ACCESS_KEY"],
            'aws_session_token': st.secrets.get("AWS_SESSION_TOKEN"),
            # 'region_name': st.secrets.get("AWS_REGION", "us-east-1")
            'region_name': st.secrets.get("AWS_REGION", "us-west-2")
        }
    except KeyError:
        return {
            'aws_access_key_id': os.environ.get('AWS_ACCESS_KEY_ID'),
            'aws_secret_access_key': os.environ.get('AWS_SECRET_ACCESS_KEY'),
            'aws_session_token': os.environ.get('AWS_SESSION_TOKEN'),
            # 'region_name': os.environ.get('AWS_REGION', 'us-east-1')
            'region_name': os.environ.get('AWS_REGION', 'us-west-2')
        }

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

# Initialize session state
init_state()

# Set up AWS session using credentials
try:
    # Create a session with the provided credentials
    session = boto3.Session(**get_aws_credentials())

    # Test the session
    sts_client = session.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]
    st.sidebar.success(f"Connected to AWS Account: {account_id}")

    # Create AWS clients
    dynamodb = session.resource('dynamodb')
    bedrock_agent_runtime_client = session.client('bedrock-agent-runtime')

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
