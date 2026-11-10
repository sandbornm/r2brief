import ts from 'typescript';

const HELPER = 'muiIconComponent';
const NAMESPACE_HELPER = 'muiIconNamespace';

function isIconBarrel(specifier: string): boolean {
  return specifier === '@mui/icons-material';
}

export function isAppSourceModule(id: string): boolean {
  const filename = id.split('?', 1)[0].replace(/\\/g, '/');
  return filename.includes('/src/') && !filename.includes('/node_modules/');
}

function rawBinding(local: string): string {
  return `__muiIcon_${local}`;
}

function quoteFor(code: string, source: ts.SourceFile, literal: ts.StringLiteral): string {
  return code[literal.getStart(source)] === "'" ? "'" : '"';
}

export function rewriteMuiIconImports(code: string, helperSpecifier: string): string {
  const source = ts.createSourceFile('module.tsx', code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const chunks: string[] = [];
  let cursor = 0;
  let rewrote = false;
  const helpers = new Set<string>();

  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause || statement.importClause.isTypeOnly) {
      continue;
    }
    if (!ts.isStringLiteral(statement.moduleSpecifier)) {
      continue;
    }
    const specifier = statement.moduleSpecifier.text;
    if (specifier !== '@mui/icons-material' && !specifier.startsWith('@mui/icons-material/')) {
      continue;
    }

    const clause = statement.importClause;
    const defaultLocal = clause.name?.text;
    const named = clause.namedBindings && ts.isNamedImports(clause.namedBindings)
      ? clause.namedBindings.elements
      : [];
    const namespace = clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)
      ? clause.namedBindings.name.text
      : undefined;
    const valueNamed = named.filter((element) => !element.isTypeOnly);
    const typeNamed = named.filter((element) => element.isTypeOnly);
    const locals = [defaultLocal, namespace, ...valueNamed.map((element) => element.name.text)].filter(
      (local): local is string => Boolean(local),
    );
    if (locals.length === 0 || locals.some((local) => local.startsWith('__muiIcon_'))) {
      continue;
    }

    const quote = quoteFor(code, source, statement.moduleSpecifier);
    const bindings: string[] = [];
    const consts: string[] = [];
    if (defaultLocal) {
      const raw = rawBinding(defaultLocal);
      bindings.push(raw);
      consts.push(`const ${defaultLocal} = ${HELPER}(${raw});`);
      helpers.add(HELPER);
    }
    if (namespace) {
      const raw = rawBinding(namespace);
      bindings.push(`* as ${raw}`);
      if (isIconBarrel(specifier)) {
        consts.push(`const ${namespace} = ${NAMESPACE_HELPER}(${raw});`);
        helpers.add(NAMESPACE_HELPER);
      } else {
        consts.push(`const ${namespace} = ${HELPER}(${raw});`);
        helpers.add(HELPER);
      }
    }
    const namedParts = [
      ...valueNamed.map((element) => {
        const imported = (element.propertyName ?? element.name).text;
        const raw = rawBinding(element.name.text);
        consts.push(`const ${element.name.text} = ${HELPER}(${raw});`);
        helpers.add(HELPER);
        return `${imported} as ${raw}`;
      }),
      ...typeNamed.map((element) => {
        const imported = (element.propertyName ?? element.name).text;
        const alias = element.propertyName ? ` as ${element.name.text}` : '';
        return `type ${imported}${alias}`;
      }),
    ];
    if (namedParts.length > 0) {
      bindings.push(`{ ${namedParts.join(', ')} }`);
    }

    const start = statement.getStart(source);
    const lineStart = code.lastIndexOf('\n', start - 1) + 1;
    const prefix = code.slice(lineStart, start);
    const indent = /^\s*$/.test(prefix) ? prefix : '';
    const replacement = `import ${bindings.join(', ')} from ${quote}${specifier}${quote};\n${consts
      .map((line) => `${indent}${line}`)
      .join('\n')}`;
    chunks.push(code.slice(cursor, start));
    chunks.push(replacement);
    cursor = statement.getEnd();
    rewrote = true;
  }

  if (!rewrote) {
    return code;
  }
  chunks.push(code.slice(cursor));
  const next = chunks.join('');
  const helperNames = [HELPER, NAMESPACE_HELPER].filter((name) => helpers.has(name));
  const helperImport = `import { ${helperNames.join(', ')} } from ${JSON.stringify(helperSpecifier)};\n`;
  if (next.includes(helperImport)) {
    return next;
  }
  return helperImport + next;
}
