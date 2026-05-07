import fs from 'fs';

let content = fs.readFileSync('src/App.tsx', 'utf8');

const contactsStart = content.indexOf('/* ─── Contacts tab ─── */');
const keysStart = content.indexOf('/* ─── Keys tab ─── */');

const before = content.substring(0, contactsStart);
const after = content.substring(keysStart);

const newContacts = `/* ─── Contacts tab ─── */

\tfunction renderContactsTab() {
\t\treturn (
\t\t\t<ContactsTab
\t\t\t\tcontacts={contacts}
\t\t\t\tcontactError={contactError}
\t\t\t\tcontactsLoading={contactsLoading}
\t\t\t\tcopyPublicStatus={copyPublicStatus}
\t\t\t\tonCopyPublicKey={handleCopyPublicKey}
\t\t\t\tonOpenAdd={() => openContactModal()}
\t\t\t\tonOpenEdit={openContactModal}
\t\t\t\tonDelete={handleDeleteContact}
\t\t\t/>
\t\t);
\t}

\t`;

let finalBefore = before;
if (!finalBefore.includes('ContactsTab')) {
    finalBefore = finalBefore.replace(
        /import \{ KeysTab \} from "\.\/components\/tabs\/KeysTab";\n/,
        `import { KeysTab } from "./components/tabs/KeysTab";\nimport { ContactsTab } from "./components/tabs/ContactsTab";\n`
    );
}

fs.writeFileSync('src/App.tsx', finalBefore + newContacts + after);
console.log("Contacts patched!");
