import hkey

def test_no_options():
    result = hkey.run()
    assert result.returncode == 2
    assert  "Usage: hkey [OPTIONS] <COMMAND>" in result.stderr

def test_help():
    result = hkey.run("--help")
    assert result.returncode == 0

    output = result.stdout + result.stderr
    assert  "Usage: hkey [OPTIONS] <COMMAND>" in output
    assert  "Connection Options:" in output
    assert  "Output Options:" in output
    assert  "Global Options:" in output

def test_version():
    result = hkey.run('--version')
    assert result.returncode == 0
    assert 'Hierarkey CLI' in result.stdout + result.stderr