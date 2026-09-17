from baseline.vendors import fetch,source_by_id,Page
page=Page();body=fetch(source_by_id('rhel'));page.feed(body.decode('utf-8','replace'))
print('bytes',len(body),'rows',len(page.rows))
for row in page.rows[:12]:print(repr(row))
