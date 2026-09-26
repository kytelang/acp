# acp-web

The documentation site for **Varman** (the Agent Control Plane, ACP): runtime authorization and
verifiable evidence for what AI agents do. Built with VitePress, mirroring the structure of
`kaidb-web`.

## Develop

```sh
npm install
npm run dev        # local preview at http://localhost:5173
npm run build      # production build into .vitepress/dist
```

## Deploy

The site deploys to Firebase Hosting, the same as `kaidb-web` and `kyte-web`.

```sh
npm run build
npx firebase deploy --only hosting:acpdocs
```

`firebase.json` targets the `acpdocs` hosting site under the `kyteweb` Firebase project (see
`.firebaserc`). Create that hosting site in the Firebase console before the first deploy, or repoint
`firebase.json` and `.firebaserc` at your own project and site.

## Content

The landing page lives in `.vitepress/theme/Home.vue`; the shared brand palette and layout are in
`.vitepress/theme/custom.css` (reused from `kaidb-web`). The guide lives in `guide/` as fifteen
chapters, one per component of the stack, plus an index. Navigation and the sidebar are defined in
`.vitepress/config.mts`.
