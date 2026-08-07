#!/usr/bin/env node
'use strict';

// Uruchamia testy opakowania i ODMAWIA, gdy nie ma czego uruchomić.
//
// Dwa błędy naraz, oba znalezione 7.08 i oba tego samego rodzaju — ścieżka, której nikt nie wykonał.
//
// 1. `npm test` było ustawione na `node --test test/`. Na Node 22 ta forma nie uruchamia katalogu,
//    tylko próbuje wczytać go jako moduł i pada z MODULE_NOT_FOUND. Czyli udokumentowana komenda
//    projektu nie działała, podczas gdy same testy przechodziły 9/9 uruchomione na pliku. CI
//    wywoływało dokładnie tę zepsutą formę i nigdy się o tym nie dowiedziało, bo zadanie `npm`
//    zależy od `build`, a `build` padał od 28.07 na uprawnieniach.
//
// 2. Oczywista poprawka — samo `node --test` — ma gorszą wadę: w katalogu BEZ testów kończy się
//    kodem 0. Zero testów wygląda wtedy identycznie jak komplet zdanych. Sprawdzone wprost.
//
// Stąd ten plik: wyszukaj pliki testów, odmów przy zerze, a dopiero potem uruchom. Wyszukiwanie
// jest rekurencyjne, więc nowy podkatalog nie wypadnie po cichu z pakietu.

const { readdirSync, statSync } = require('node:fs');
const { join, relative } = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = join(__dirname, '..');
const TEST_DIR = join(ROOT, 'test');

function collect(dir) {
  let out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out = out.concat(collect(p));
    else if (/\.test\.(c|m)?js$/.test(name)) out.push(p);
  }
  return out;
}

let files = [];
try {
  files = collect(TEST_DIR);
} catch (err) {
  console.error(`ODMOWA: nie da się odczytać ${relative(ROOT, TEST_DIR)} — ${err.message}`);
  process.exit(3);
}

if (files.length === 0) {
  console.error('ODMOWA: nie znaleziono ani jednego pliku *.test.js.');
  console.error('Zero testów nie jest sukcesem, a `node --test` w pustym katalogu kończy się zerem.');
  process.exit(3);
}

console.log(`uruchamiam ${files.length} plik(ów) testów:`);
for (const f of files) console.log(`  ${relative(ROOT, f)}`);

const r = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit', cwd: ROOT });
process.exit(r.status === null ? 1 : r.status);
