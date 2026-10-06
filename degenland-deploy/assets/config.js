/* DegenLand · impostazioni di lancio (l'unico file da toccare)
   preview: true  = tutti vedono la schermata "Coming soon"
            false = sito e gioco aperti a tutti (lancio)
            La regola qui sotto la spegne da sola sulla versione test (test.*).
   previewKey: chi apre https://degenland.site/?preview=dl-7e82430e entra e vede il sito vero
               su quel browser. Con ?preview=off si torna alla schermata preview.
               Sulla versione test, ?preview=show mostra la schermata preview per provarla.
   launchAt: data e ora del lancio per il conto alla rovescia (ora italiana, +02:00).
   social: lascia '' per nascondere un canale; incolla il link per mostrarlo ovunque. */
window.DEGENLAND = {
  preview: !location.hostname.startsWith('test.'),
  previewKey: 'dl-7e82430e',
  launchAt: '2026-10-09T18:00:00+02:00',
  social: {
    x: '',
    telegram: 'https://t.me/DegenLandchannel',
    discord: 'https://discord.gg/edEeZKzge'
  }
};
