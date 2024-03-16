export function nowMilliseconds() {
  return Math.floor(performance.now())
}

export async function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}
