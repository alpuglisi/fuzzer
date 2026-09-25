{{-- Hand-authored (CC-LAB-0239, docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md step 3):
     a GET client page for the POST-only /example/account_settings api cell
     (LABGEN-MA-0003/0004, a JSON mass-assignment API per
     docs/LAB_BROWSABLE_APPS_PLAN.md's own "JSON mass-assignment APIs...
     stay JSON" test) -- the minimal inline fetch() a real frontend would
     use, per that same plan's client-page pattern. Never posted
     automatically on page load. --}}
@extends('layouts.site')
@section('title', 'Account settings')
@section('content')
    <h2>Account settings</h2>
    <p>
        <label>Display name <input id="display_name" value="New name"></label><br>
        <label>Bio <input id="bio" value="New bio"></label><br>
        <button onclick="saveSettings()">Save</button>
    </p>
    <pre id="settings-result">(not saved yet)</pre>
    <script>
    function saveSettings() {
        fetch('/example/account_settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                display_name: document.getElementById('display_name').value,
                bio: document.getElementById('bio').value,
            }),
        })
            .then(r => r.text())
            .then(t => { document.getElementById('settings-result').textContent = t; });
    }
    </script>
@endsection
