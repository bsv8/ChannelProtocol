/**
 * 对协议 JSON 值做结构复制和递归冻结。
 *
 * TypeScript 的 readonly 只约束编译期；验证结果必须在运行时也切断调用方对
 * body/content/locators 等嵌套对象的写入路径。
 */
export function cloneAndFreeze<T>(value: T): T {
  return deepFreeze(cloneValue(value, new WeakMap<object, unknown>())) as T;
}

/** 只冻结已经由 SDK 创建的对象；用于设置 brand 后的最终快照。 */
export function freezeDeep<T>(value: T): T {
  return deepFreeze(value, new WeakSet<object>());
}

function cloneValue(value: unknown, seen: WeakMap<object, unknown>): unknown {
  if (value === null || typeof value !== "object") return value;
  const existing = seen.get(value);
  if (existing !== undefined) return existing;

  if (value instanceof Uint8Array) {
    const copy = new Uint8Array(value);
    seen.set(value, copy);
    return copy;
  }

  if (Array.isArray(value)) {
    const copy: unknown[] = [];
    seen.set(value, copy);
    for (const item of value) copy.push(cloneValue(item, seen));
    return copy;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    // JCS 会在调用方输入校验时拒绝非普通 object；这里保留一个独立快照，
    // 让错误路径也不会意外持有业务对象的引用。
    return value;
  }

  const copy = Object.create(prototype) as Record<string, unknown>;
  seen.set(value, copy);
  for (const key of Object.keys(value)) {
    Object.defineProperty(copy, key, {
      value: cloneValue((value as Record<string, unknown>)[key], seen),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return copy;
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor && "value" in descriptor) deepFreeze(descriptor.value, seen);
  }
  return Object.freeze(value);
}
