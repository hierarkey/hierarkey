import pytest
import hkey
import helpers

@pytest.fixture(scope="session", autouse=True)
def login_admin_once():
    """
    Ensure we are logged in as admin once per test session.

    This relies on the global AUTH_TOKEN in runner.py and avoids
    logging in for every single test.
    """
    hkey.login()
    yield
    hkey.logout()


@pytest.fixture(autouse=True)
def clean_namespaces_before_each_test():
    """
    Guarantee a clean slate for each test.

    Called automatically before and after every test function, so
    they don't interfere with each other via leftover namespaces.
    """
    print("Clearing all namespaces before test...")
    helpers.clear_all_namespaces()
    helpers.clear_all_rbac()
    helpers.clear_all_pats()
    yield
    print("Clearing all namespaces after test...")
    helpers.clear_all_namespaces()
    helpers.clear_all_rbac()
    helpers.clear_all_pats()


@pytest.fixture(scope="session", autouse=True)
def login_admin():
    """
    Ensure we are logged in as admin once per test session.
    This removes any dependence on test execution order.
    """
    result = hkey.run("auth", "login", "--name", "admin", "--insecure-password", "admin_test_password")
    assert result.returncode == 0
