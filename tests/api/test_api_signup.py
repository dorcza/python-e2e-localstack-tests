import pytest
from api.post_sign_up import SignUp
from generators.user_generator import get_random_user
import requests
import logging

# Configure logging to display debug information
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

@pytest.fixture
def sign_up_api():
    return SignUp()

def make_request_and_log(sign_up_api, user):
    try:
        response = sign_up_api.api_call(user)
        logging.info(f"Request made:\nHTTP Response Code: {response.status_code}\nBody: {response.json()}")
        return response
    except requests.HTTPError as e:
        logging.error(f"HTTP Error encountered:\nHTTP Response Code: {e.response.status_code}\nError: {str(e)}")
        return e.response  # Return the response so we can still check the status code in our tests

def test_successful_user_registration(sign_up_api: SignUp):
    user = get_random_user()
    response = make_request_and_log(sign_up_api, user)
    assert response.status_code == 201, "Expected status code 201"
    assert 'token' in response.json(), "Token should not be None"

def test_field_validation_failed(sign_up_api: SignUp):
    user = get_random_user()
    invalid_emails = ["not_an_email", "missing_domain@.com", "missing_at_symbol.com"]
    for email in invalid_emails:
        user.email = email
        response = make_request_and_log(sign_up_api, user)
        assert response.status_code == 400, f"Expected status code 400 for invalid email: {email}"

def test_access_denied(sign_up_api: SignUp):
    user = get_random_user()
    user.roles = ["ROLE_UNAUTHORIZED"]
    response = make_request_and_log(sign_up_api, user)
    assert response.status_code == 403, "Expected status code 403"

def test_username_already_in_use(sign_up_api: SignUp):
    user = get_random_user()
    user.username = "existing_user"
    response = make_request_and_log(sign_up_api, user)
    assert response.status_code == 422, "Expected status code 422"

def test_internal_server_error(sign_up_api: SignUp):
    user = get_random_user()
    user.email = "trigger@server.error"
    response = make_request_and_log(sign_up_api, user)
    assert response.status_code == 500, "Expected status code 500"

def test_empty_payload(sign_up_api: SignUp):
    user = get_random_user()
    user.username = ""  # Simulate empty payload
    user.email = ""
    response = make_request_and_log(sign_up_api, user)
    assert response.status_code == 400, "Expected status code 400 for empty payload"

def test_invalid_payload_structure(sign_up_api: SignUp):
    user = get_random_user()
    user.email = ""  # Remove required field to simulate invalid structure
    response = make_request_and_log(sign_up_api, user)
    assert response.status_code == 400, "Expected status code 400 for invalid payload structure"
