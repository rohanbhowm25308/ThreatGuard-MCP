import io
from app import app

def upload(payload, filename='sample.csv'):
    with app.test_client() as client:
        return client.post('/api/preview-upload', data={'file': (io.BytesIO(payload), filename)}, content_type='multipart/form-data')

def test_bundled_csv():
    from pathlib import Path
    data = (Path(__file__).resolve().parents[1] / 'demo_data.csv').read_bytes()
    result = upload(data)
    assert result.status_code == 200
    assert len(result.json['items']) == 2

def test_excel_semicolon_bom():
    data = '\ufeffCVE ID;Vendor;Product;Description\nCVE-2024-3400;Example;Device;Test\n'.encode('utf-8')
    result = upload(data)
    assert result.status_code == 200
    assert result.json['items'][0]['vendorProject'] == 'Example'

def test_bad_id_gives_row():
    result = upload(b'CVE ID,Vendor\nnot-a-cve,Example\n')
    assert result.status_code == 400
    assert 'Row 2' in result.json['error']

def test_missing_header():
    result = upload(b'Identifier,Vendor\nCVE-2024-3400,Example\n')
    assert result.status_code == 400
    assert 'Missing CVE ID column' in result.json['error']
