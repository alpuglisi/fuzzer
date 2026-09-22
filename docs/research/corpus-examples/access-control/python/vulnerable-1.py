"""
Flask IDOR (Insecure Direct Object Reference) detection prompt.
"""

FLASK_IDOR_PROMPT = """## IDOR (Insecure Direct Object Reference) Detection in Flask

### What to Look For

1. **URL parameters used directly in SQLAlchemy queries without ownership check**
2. **Missing filter_by(user_id=current_user.id)**
3. **Flask-RESTful resources without ownership validation**

### Flask-Specific Patterns

**Direct Query (Vulnerable)**:
```python
# VULNERABLE: No ownership check
@app.route('/api/invoices/<int:invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    return jsonify(invoice.to_dict())  # Any user can view any invoice

# SAFE: Scoped to user
@app.route('/api/invoices/<int:invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.filter_by(
        id=invoice_id, user_id=current_user.id
    ).first_or_404()
    return jsonify(invoice.to_dict())
```

**db.session.get (Vulnerable)**:
```python
# VULNERABLE: Direct primary key lookup
@app.route('/api/documents/<int:doc_id>', methods=['PUT'])
@login_required
def update_document(doc_id):
    doc = db.session.get(Document, doc_id)  # No ownership check!
    doc.title = request.json['title']
    db.session.commit()
```

**Flask-RESTful (Vulnerable)**:
```python
# VULNERABLE: Resource without ownership
class OrderResource(Resource):
    @login_required
    def get(self, order_id):
        order = Order.query.get_or_404(order_id)
        return marshal(order, order_fields)  # Any user's order!

    @login_required
    def delete(self, order_id):
        order = Order.query.get_or_404(order_id)
        db.session.delete(order)  # Can delete anyone's order!
        db.session.commit()
```

**Marshmallow Nested (Vulnerable)**:
```python
# VULNERABLE: User can set owner in request body
class ProjectSchema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str(required=True)
    owner_id = fields.Int()  # Writable! User can claim any owner
```

### Search Patterns

1. `grep` for: `\\.get_or_404\\(`, `\\.get\\(`, `db\\.session\\.get\\(`
2. `grep` for: `query\\.filter_by\\(id=` -- check for user scoping
3. Check Flask-RESTful `Resource` classes for ownership checks
4. Look for `request.args`, `request.form`, URL params flowing to queries

### Severity Assessment

- **Critical**: Access to other users' sensitive data (PII, financial)
- **High**: Modification/deletion of other users' resources
- **Medium**: Read access to non-sensitive resources
- **Low**: Informational leaks with no impact
"""
