interface Toast {
  id: number;
  message: string;
  tone: 'success' | 'error';
}

let nextId = 1;

export const toasts = $state<{ items: Toast[] }>({ items: [] });

export function notify(message: string, tone: Toast['tone'] = 'success') {
  const id = nextId++;
  toasts.items = [...toasts.items, { id, message, tone }];
  setTimeout(() => dismiss(id), 4000);
}

export function dismiss(id: number) {
  toasts.items = toasts.items.filter((toast) => toast.id !== id);
}
