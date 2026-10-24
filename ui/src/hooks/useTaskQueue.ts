import { api } from '../api/client'

export function useTaskQueue(sessionId: string) {
  async function queueTask(type: string, args: Record<string, unknown>): Promise<string> {
    const { data } = await api.post('/api/v1/tasks', {
      session_id: sessionId,
      type,
      args: btoa(JSON.stringify(args)),
    })
    return data.task_id as string
  }

  async function pollOutput(taskId: string, maxWaitMs = 120_000): Promise<Uint8Array | null> {
    const interval = 2000
    const attempts = Math.ceil(maxWaitMs / interval)
    for (let i = 0; i < attempts; i++) {
      await sleep(interval)
      try {
        const { data } = await api.get(`/api/v1/tasks/${taskId}`)
        if (data.status === 'failed') {
          const msg = data.output
            ? new TextDecoder().decode(Uint8Array.from(atob(data.output), c => c.charCodeAt(0)))
            : 'task failed'
          throw new Error(msg.trim() || 'task failed')
        }
        if (data.status === 'complete') {
          if (!data.output) return null
          return Uint8Array.from(atob(data.output), c => c.charCodeAt(0))
        }
      } catch { /* continue */ }
    }
    return null
  }

  return { queueTask, pollOutput }
}

function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)) }
