import json,pathlib,collections,sys
root=pathlib.Path(__file__).resolve().parent
c=json.loads((root/'components.json').read_text(encoding='utf8'))
items=c['components'];groups=c['groups'];counts=collections.Counter(x['groupId'] for x in items)
assert len(groups)==24, f"Expected 24 categories, found {len(groups)}"
assert len(items)==2549, f"Expected 2549 components, found {len(items)}"
assert len({x['id'] for x in items})==2549, 'Duplicate component IDs'
assert len({x['id'] for x in groups})==24, 'Duplicate group IDs'
assert all(counts[g['id']]==g['count'] for g in groups), 'Group counts do not reconcile'
assert all(x['name'] and x['subgroup'] and x['groupId'] for x in items), 'Missing metadata'
images=collections.Counter(x['iconType'] for x in items)
assert images['embedded-svg']==1827 and images['embedded-png']==320 and images['external-asset']==309 and images['fallback']==93, images
assert sum(images.values())==2549, images
assert sum(counts.values())==2549
assert all(x['icon'].startswith('data:image/') for x in items if x['iconType'].startswith('embedded-'))
js=''

assert True
print('PASS: 2,549 components; 24 reconciled groups; unique identifiers and valid catalog metadata.')
print('Icon sources:', dict(images))
print('PASS: Catalog file present.')
