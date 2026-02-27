<script lang="ts">
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import { stringifyError } from 'common/errors'
    import { Button } from '@sveltestrap/sveltestrap'

    let error: string | undefined = $state()
    let downloading = $state(false)

    function downloadBlob (content: string, filename: string, mime: string) {
        const blob = new Blob([content], { type: mime })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        a.click()
        URL.revokeObjectURL(url)
    }

    async function downloadKeys () {
        error = undefined
        downloading = true
        try {
            const res = await fetch('/warpgate/admin/api/ssh/break-glass-keys', {
                credentials: 'include',
            })
            if (!res.ok) {
                const text = await res.text()
                throw new Error(text || `HTTP ${res.status}`)
            }
            const data = (await res.json()) as {
                keys: Array<{ filename: string; content: string }>
                readme: string
            }
            for (const key of data.keys) {
                downloadBlob(key.content, key.filename, 'application/x-pem-file')
            }
            downloadBlob(data.readme, 'README.txt', 'text/plain')
        } catch (e) {
            error = await stringifyError(e as Error)
        } finally {
            downloading = false
        }
    }
</script>

<div class="page-summary-bar">
    <h1>Emergency Procedure and Access</h1>
</div>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

<Alert color="warning">
    These are Warpgate's <strong>client</strong> SSH keys. Use them only in an emergency when Warpgate is down to connect directly to targets. Store them securely. Each download is logged.
</Alert>

<h2>OpenSSH / terminal</h2>
<ol>
    <li>Save each key file (e.g. <code>client-ed25519</code>, <code>client-rsa</code>) to a secure location.</li>
    <li>Set permissions: <code>chmod 600 &lt;keyfile&gt;</code></li>
    <li>Connect: <code>ssh -i &lt;keyfile&gt; &lt;user&gt;@&lt;target_host&gt;</code></li>
</ol>

<h2>PuTTY (Windows)</h2>
<p>Keys are in PEM format. Convert to PuTTY's .ppk format:</p>
<ol>
    <li>Open PuTTYgen</li>
    <li>Conversions → Import key → select the PEM file</li>
    <li>Save private key (as .ppk)</li>
    <li>In PuTTY: Connection → SSH → Auth → Private key file → select the .ppk. Or load the .ppk into Pageant.</li>
    <li>Connect as usual to the target host.</li>
</ol>

<h2>Rotating keys after a breach</h2>
<p>To avoid locking yourself out, <strong>add the new public keys to all targets before removing the old ones</strong>. Use this order:</p>
<ol>
    <li>On the Warpgate server: back up then delete the client key files (e.g. <code>client-ed25519</code> and <code>client-rsa</code> in the SSH keys directory).</li>
    <li>Restart Warpgate so it generates new client keys.</li>
    <li>Get the <strong>new</strong> public keys: run <code>warpgate client-keys</code> on the server, or use Admin → Targets and view “Warpgate’s own keys” for a target.</li>
    <li>Add the new public keys to <code>authorized_keys</code> on <strong>every</strong> target that uses them. Leave the old public keys in place for now.</li>
    <li>Verify access: download the break-glass keys from this page and test <code>ssh -i &lt;keyfile&gt; user@target</code> for at least one target.</li>
    <li>Remove the old public keys from <code>authorized_keys</code> on all targets.</li>
    <li>Securely destroy old private key copies (previous downloads, backups, any stored break-glass keys).</li>
</ol>

<div class="mt-3">
    <Button color="primary" disabled={downloading} onclick={() => downloadKeys()}>
        {downloading ? 'Downloading…' : 'Download SSH keys'}
    </Button>
</div>

<style lang="scss">
    ol {
        padding-left: 1.25rem;
    }
    li {
        margin-bottom: 0.25rem;
    }
</style>
