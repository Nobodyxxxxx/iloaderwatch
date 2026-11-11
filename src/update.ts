// Deliberately no updater plugin imports in the experimental Watch build.

export async function checkForUpdates() {
    // Disabled in this unofficial experimental build: never replace it with
    // upstream binaries that do not contain this Watch patch.
    return;
}
