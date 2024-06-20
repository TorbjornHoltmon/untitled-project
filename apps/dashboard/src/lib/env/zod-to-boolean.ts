export const toBoolean = (input: string | boolean | number | undefined): boolean => {
  if (!input) {
    return false
  }

  if (typeof input === 'string') {
    input = input.replaceAll(' ', '').toLowerCase()
  }

  switch (input) {
    case true:
    case 'true':
    case 1:
    case '1':
    case 'on':
    case 'yes': {
      return true
    }
    default: {
      return false
    }
  }
}
