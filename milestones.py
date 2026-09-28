with open('app.py', 'r', encoding='utf-8') as f:
    src = f.read()

code = '''

MILESTONES_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>📋 مراحل الصفقة #{eid}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Tahoma,sans-serif;background:#07090e;color:#f1f5f9;padding:15px}
.c{max-width:700px;margin:auto;background:#111827;padding:20px;border-radius:12px;border:1px solid #1f2937}
h1{color:#38bdf8;text-align:center;font-size:20px;margin-bottom:5px}
.badge{text-align:center;color:#10b981;font-size:12px;margin-bottom:20px}
.sec{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151;margin-bottom:12px}
.sec h3{color:#cbd5e1;margin-bottom:12px;font-size:15px;border-bottom:1px solid #374151;padding-bottom:8px}
label{display:block;color:#94a3b8;font-size:12px;margin:8px 0 4px}
input{width:100%;padding:11px;background:#0b0f19;color:#fff;border:1px solid #4b5563;border-radius:8px;font-size:14px}
button{width:100%;padding:12px;background:#0284c7;color:#fff;border:none;border-radius:8px;font-weight:bold;font-size:14px;cursor:pointer;margin-top:10px}
.bs{background:#10b981}.bw{background:#d97706}
.item{background:#0b0f19;padding:14px;margin-top:8px;border-radius:8px;border-right:4px solid #fbbf24;font-size:13px}
.item.done{border-right-color:#10b981;opacity:0.7}
.item b{color:#fbbf24}
.item.done b{color:#10b981}
.info{background:#1e3a8a;padding:10px;border-radius:8px;font-size:12px;color:#bfdbfe;margin-bottom:12px;line-height:1.6}
.back{display:block;text-align:center;color:#38bdf8;text-decoration:none;margin-top:15px;font-size:13px}
.total{text-align:center;color:#10b981;font-size:14px;margin:8px 0;font-weight:bold}
</style>
</head>
<body>
<div class="c">
<h1>📋 مراحل الصفقة #{eid}</h1>
<div class="badge">البائع: {seller} | المشتري: {buyer}</div>
<div class="total">💰 إجمالي الصفقة: {amount} $</div>

<div class="info">
📌 المراحل تقسم الصفقة لأجزاء. البائع يضيف مرحلة، والمشتري يحرر كل مرحلة بعد استلامها.
</div>

{add_form}

<div class="sec">
<h3>📋 المراحل ({count})</h3>
{list_html}
</div>

<a href="/" class="back">← العودة للمنصة</a>
</div>
</body>
</html>
"""


@app.route('/escrow/<int:eid>/milestones')
@login_required
def milestones_page(eid):
    conn = get_db()
    e = conn.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        conn.close()
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 غير مخول</h1>"
    
    rows = conn.execute("SELECT * FROM milestones WHERE escrow_id=? ORDER BY order_num", (eid,)).fetchall()
    total_added = sum(r['amount'] for r in rows)
    remaining = e['amount'] - total_added
    
    # نموذج الإضافة - يظهر فقط للبائع
    add_form = ""
    if session['user'] == e['seller'] and e['status'] == 'LOCKED_SECURE' and remaining > 0:
        add_form = f"""
        <form method="POST" action="/escrow/{eid}/milestone/add" class="sec">
        <h3>➕ إضافة مرحلة جديدة</h3>
        <label>عنوان المرحلة</label>
        <input type="text" name="title" required placeholder="مثال: التصميم" maxlength="100">
        <label>المبلغ (المتبقي: {remaining:.2f} $)</label>
        <input type="number" name="amount" step="0.01" min="0.01" max="{remaining}" required placeholder="0.00">
        <button type="submit">➕ إضافة المرحلة</button>
        </form>
        """
    
    # قائمة المراحل
    list_html = ""
    if not rows:
        list_html = "<p style='color:#6b7280;text-align:center;padding:15px'>لا توجد مراحل بعد</p>"
    for r in rows:
        cls = "done" if r['status'] == 'RELEASED' else ""
        actions = ""
        if r['status'] == 'PENDING' and session['user'] == e['buyer'] and e['status'] == 'LOCKED_SECURE':
            actions = f"<form method='POST' action='/escrow/{eid}/milestone/{r['id']}/release' style='margin-top:8px'><button class='bs' type='submit'>✅ تحرير هذه المرحلة ({r['amount']}$)</button></form>"
        status_icon = "✅" if r['status'] == 'RELEASED' else "⏳"
        list_html += f"<div class='item {cls}'><b>{status_icon} {r['order_num']}. {r['title']}</b><br>المبلغ: <b>{r['amount']} $</b> | الحالة: {r['status']}{actions}</div>"
    
    conn.close()
    html = MILESTONES_HTML.replace("{eid}", str(eid)).replace("{seller}", e['seller']).replace("{buyer}", e['buyer'] or '—')
    html = html.replace("{amount}", f"{e['amount']:.2f}").replace("{count}", str(len(rows)))
    html = html.replace("{add_form}", add_form).replace("{list_html}", list_html)
    return html


@app.route('/escrow/<int:eid>/milestone/add', methods=['POST'])
@login_required
def milestone_add(eid):
    title = (request.form.get('title') or '').strip()[:100]
    try:
        amount = round(float(request.form.get('amount', 0)), 2)
    except:
        amount = 0
    if not title or amount <= 0:
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>❌ بيانات غير صالحة</h1>"
    
    conn = get_db()
    e = conn.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or e['seller'] != session['user'] or e['status'] != 'LOCKED_SECURE':
        conn.close()
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 غير مخول</h1>"
    
    total = conn.execute("SELECT COALESCE(SUM(amount),0) as s FROM milestones WHERE escrow_id=?", (eid,)).fetchone()['s']
    if total + amount > e['amount']:
        conn.close()
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>❌ المبلغ يتجاوز قيمة الصفقة</h1>"
    
    order = conn.execute("SELECT COALESCE(MAX(order_num),0)+1 as n FROM milestones WHERE escrow_id=?", (eid,)).fetchone()['n']
    conn.execute("INSERT INTO milestones (escrow_id, title, amount, order_num) VALUES (?,?,?,?)", (eid, title, amount, order))
    conn.commit()
    conn.close()
    return f"<html><head><meta charset='UTF-8'><meta http-equiv='refresh' content='0;url=/escrow/{eid}/milestones'></head></html>"


@app.route('/escrow/<int:eid>/milestone/<int:mid>/release', methods=['POST'])
@login_required
def milestone_release(eid, mid):
    with db_lock:
        conn = get_db(); c = conn.cursor()
        try:
            c.execute("BEGIN IMMEDIATE")
            m = c.execute("SELECT * FROM milestones WHERE id=? AND escrow_id=?", (mid, eid)).fetchone()
            if not m or m['status'] != 'PENDING':
                c.execute("ROLLBACK"); return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>❌ غير متاح</h1>"
            e = c.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
            if not e or e['buyer'] != session['user']:
                c.execute("ROLLBACK"); return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 المشتري فقط</h1>"
            if e['status'] != 'LOCKED_SECURE':
                c.execute("ROLLBACK"); return "<h1 style='color:#fbbf24;text-align:center;font-family:Tahoma;padding:50px'>⚠️ الصفقة غير نشطة</h1>"
            
            rate = c.execute("SELECT commission_rate FROM treasury WHERE id=1").fetchone()['commission_rate']
            comm = round(m['amount'] * rate / 100.0, 2)
            net = round(m['amount'] - comm, 2)
            
            c.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (net, e['seller']))
            c.execute("UPDATE milestones SET status='RELEASED' WHERE id=?", (mid,))
            c.execute("UPDATE treasury SET balance=balance+?, total_commission=total_commission+?, total_locked=total_locked-?, total_released=total_released+? WHERE id=1", (comm, comm, m['amount'], m['amount']))
            c.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)",
                      (e['seller'], "MILESTONE_RELEASE", net, f"مرحلة {m['title']} صفقة #{eid}"))
            c.execute("COMMIT")
            conn.close()
            try:
                notify(e['seller'], "💰 مرحلة محررة", f"استلمت {net}$ لمرحلة '{m['title']}'")
            except: pass
            return f"<html><head><meta charset='UTF-8'><meta http-equiv='refresh' content='1;url=/escrow/{eid}/milestones'></head><body style='background:#07090e;color:#10b981;text-align:center;font-family:Tahoma;padding:50px'><h1>✅ تم تحرير {net}$</h1></body></html>"
        except Exception as ex:
            c.execute("ROLLBACK")
            return f"<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>خطأ: {ex}</h1>"


# ============ التحرير التلقائي ============
def auto_release_check():
    """يفحص الصفقات القديمة ويحررها تلقائياً"""
    import time as _t
    while True:
        try:
            _t.sleep(300)  # كل 5 دقائق
            with db_lock:
                conn = get_db()
                c = conn.cursor()
                try:
                    c.execute("BEGIN IMMEDIATE")
                    # الصفقات المفتوحة لأكثر من 7 أيام
                    rows = c.execute('''SELECT e.* FROM escrows e 
                        WHERE e.status='LOCKED_SECURE' 
                        AND julianday('now') - julianday(e.updated_at) > 7
                        AND NOT EXISTS (SELECT 1 FROM milestones WHERE escrow_id=e.id AND status='PENDING')''').fetchall()
                    for e in rows:
                        rate = c.execute("SELECT commission_rate FROM treasury WHERE id=1").fetchone()['commission_rate']
                        comm = round(e['amount'] * rate / 100.0, 2)
                        net = round(e['amount'] - comm, 2)
                        c.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (net, e['seller']))
                        c.execute("UPDATE escrows SET status='RELEASED', updated_at=CURRENT_TIMESTAMP WHERE id=?", (e['id'],))
                        c.execute("UPDATE treasury SET balance=balance+?, total_commission=total_commission+?, total_locked=total_locked-?, total_released=total_released+? WHERE id=1", (comm, comm, e['amount'], e['amount']))
                        c.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)",
                                  (e['seller'], "AUTO_RELEASE", net, f"تحرير تلقائي #{e['id']}"))
                    if rows:
                        c.execute("COMMIT")
                        print(f"[AUTO] حرر {len(rows)} صفقة")
                    else:
                        c.execute("ROLLBACK")
                except Exception as ex:
                    try: c.execute("ROLLBACK")
                    except: pass
                finally:
                    conn.close()
        except Exception as e:
            print(f"[AUTO] {e}")


# بدء خيط التحرير التلقائي
try:
    import threading as _th
    _th.Thread(target=auto_release_check, daemon=True).start()
    print("✅ خيط التحرير التلقائي يعمل")
except Exception as _e:
    print(f"[AUTO-THREAD] {_e}")

'''

if 'def milestones_page' not in src:
    if "if __name__ == '__main__':" in src:
        src = src.replace("if __name__ == '__main__':", code + "\nif __name__ == '__main__':", 1)
        print('OK-MILESTONES')
    else:
        src = src.rstrip() + code + '\n\nif __name__ == "__main__":\n    app.run(host="127.0.0.1", port=5000, debug=False)\n'
        print('OK-APPENDED')

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(src)
print('DONE')
