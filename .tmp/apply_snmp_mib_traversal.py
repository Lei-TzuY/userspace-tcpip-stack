from pathlib import Path

path = Path('src/snmp.rs')
text = path.read_text()

old = '''    pub fn get(&self, oid: &str) -> Option<&SnmpValue> {
        self.objects.get(oid)
    }

    pub fn set(&mut self, oid: &str, val: SnmpValue) {
        self.objects.insert(oid.to_string(), val);
    }
'''

new = '''    pub fn get(&self, oid: &str) -> Option<&SnmpValue> {
        self.objects.get(oid)
    }

    pub fn set(&mut self, oid: &str, val: SnmpValue) {
        self.objects.insert(oid.to_string(), val);
    }

    pub fn get_next(&self, oid: &str) -> Result<Option<SnmpVarbind>, SnmpError> {
        let needle = oid_arcs(oid)?;
        let next = self
            .objects
            .iter()
            .filter_map(|(candidate, value)| {
                let arcs = oid_arcs(candidate).ok()?;
                (arcs > needle).then_some((arcs, candidate, value))
            })
            .min_by(|left, right| left.0.cmp(&right.0));

        Ok(next.map(|(_, candidate, value)| SnmpVarbind {
            oid: candidate.clone(),
            value: value.clone(),
        }))
    }

    pub fn get_bulk(
        &self,
        oids: &[&str],
        non_repeaters: usize,
        max_repetitions: usize,
    ) -> Result<Vec<SnmpVarbind>, SnmpError> {
        for oid in oids {
            oid_arcs(oid)?;
        }

        let non_repeater_count = non_repeaters.min(oids.len());
        let mut results = Vec::new();
        for &oid in &oids[..non_repeater_count] {
            results.push(self.get_next(oid)?.unwrap_or_else(|| SnmpVarbind {
                oid: oid.to_string(),
                value: SnmpValue::EndOfMibView,
            }));
        }

        let mut cursors = oids[non_repeater_count..]
            .iter()
            .map(|oid| (*oid).to_string())
            .collect::<Vec<_>>();
        for _ in 0..max_repetitions {
            for cursor in &mut cursors {
                match self.get_next(cursor)? {
                    Some(varbind) => {
                        *cursor = varbind.oid.clone();
                        results.push(varbind);
                    }
                    None => results.push(SnmpVarbind {
                        oid: cursor.clone(),
                        value: SnmpValue::EndOfMibView,
                    }),
                }
            }
        }

        Ok(results)
    }
'''

if old not in text:
    raise SystemExit('SnmpMib insertion point not found')
text = text.replace(old, new, 1)

marker = '''/// In-Memory Management Information Base (MIB-II) Store
pub struct SnmpMib'''
helper = '''fn oid_arcs(oid: &str) -> Result<Vec<u64>, SnmpError> {
    let arcs = oid
        .split('.')
        .map(|arc| arc.parse::<u64>().map_err(|_| SnmpError::InvalidBerEncoding))
        .collect::<Result<Vec<_>, _>>()?;
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
        return Err(SnmpError::InvalidBerEncoding);
    }
    Ok(arcs)
}

/// In-Memory Management Information Base (MIB-II) Store
pub struct SnmpMib'''
if marker not in text:
    raise SystemExit('SnmpMib marker not found')
text = text.replace(marker, helper, 1)

tests = r'''

    #[test]
    fn test_snmp_mib_get_next_uses_numeric_oid_order() {
        let mut mib = SnmpMib::new();
        mib.set("1.3.6.1.4.1.2.0", SnmpValue::Integer(2));
        mib.set("1.3.6.1.4.1.10.0", SnmpValue::Integer(10));

        let next = mib.get_next("1.3.6.1.4.1.2.0").unwrap().unwrap();
        assert_eq!(next.oid, "1.3.6.1.4.1.10.0");
        assert_eq!(next.value, SnmpValue::Integer(10));
    }

    #[test]
    fn test_snmp_mib_get_next_returns_none_after_last_oid() {
        let mib = SnmpMib::new();
        assert_eq!(mib.get_next("2.999.0").unwrap(), None);
        assert_eq!(
            mib.get_next("1.40.0"),
            Err(SnmpError::InvalidBerEncoding)
        );
    }

    #[test]
    fn test_snmp_mib_get_bulk_expands_non_repeaters_and_repeaters() {
        let mut mib = SnmpMib::new();
        mib.set("1.3.6.1.4.1.1.0", SnmpValue::Integer(1));
        mib.set("1.3.6.1.4.1.2.0", SnmpValue::Integer(2));
        mib.set("1.3.6.1.4.1.3.0", SnmpValue::Integer(3));

        let result = mib
            .get_bulk(
                &["1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.0.0", "1.3.6.1.4.1.1.0"],
                1,
                2,
            )
            .unwrap();

        assert_eq!(result.len(), 5);
        assert_eq!(result[0].oid, "1.3.6.1.2.1.1.3.0");
        assert_eq!(result[1].oid, "1.3.6.1.4.1.1.0");
        assert_eq!(result[2].oid, "1.3.6.1.4.1.2.0");
        assert_eq!(result[3].oid, "1.3.6.1.4.1.2.0");
        assert_eq!(result[4].oid, "1.3.6.1.4.1.3.0");
    }

    #[test]
    fn test_snmp_mib_get_bulk_emits_end_of_mib_view() {
        let mib = SnmpMib::new();
        let result = mib.get_bulk(&["2.999.0"], 0, 2).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].oid, "2.999.0");
        assert_eq!(result[0].value, SnmpValue::EndOfMibView);
        assert_eq!(result[1].value, SnmpValue::EndOfMibView);
    }
'''

head, sep, tail = text.rpartition('\n}')
if not sep:
    raise SystemExit('test module closing brace not found')
text = head + tests + '\n}\n' + tail
path.write_text(text)
