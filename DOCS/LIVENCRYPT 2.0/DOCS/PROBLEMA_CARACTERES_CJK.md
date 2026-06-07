# Problema de Carga de Caracteres CJK (Chino, Coreano y Katakana) en el Editor de Plantillas

Este documento analiza por qué la función **Editor de Plantillas** no visualiza correctamente los caracteres de los idiomas **Chino**, **Coreano** y **Katakana** (mostrando en su lugar secuencias de escape Unicode como `\uXXXX` o bloques vacíos/tofus), mientras que otros alfabetos se cargan de forma correcta. Se detallan las causas de este comportamiento y las soluciones a nivel de código y de sistema operativo.

---

## 1. Descripción del Problema

En la interfaz del **Editor de Plantillas** (`TemplateEditorWindow.tsx`), al activar o cargar los alfabetos correspondientes a los idiomas asiáticos:
- **Chino**: Se muestran secuencias de texto literal o caracteres de escape.
- **Coreano**: Se visualizan códigos en lugar de los caracteres Hangul correspondientes.
- **Katakana**: Aparecen representaciones simbólicas o códigos de escape.
- **Otros idiomas** (como Alemán, Checo o Ruso): Cargan y renderizan perfectamente sus caracteres UTF-8 nativos.

Este comportamiento impide que el usuario pueda interactuar visualmente con la paleta de caracteres de forma clara para diseñar plantillas personalizadas.

---

## 2. Causas Principales

### Causa A: Secuencias de Escape Unicode sin decodificar en el Frontend

Las plantillas por defecto y los archivos guardados en formato MessagePack (`.msgpack`) pueden almacenar caracteres complejos CJK utilizando secuencias de escape de doble barra (por ejemplo, `"\\u4F60"` en lugar de `"你"`). 

Aunque el backend en Rust incluye funciones de decodificación (`decode_unicode_escapes`) al leer y procesar las plantillas, en el frontend de React existe una inconsistencia:
1. Las fuentes tipográficas de los idiomas se cargan mediante `normalizeLanguageMap` que sí aplica la función de decodificación `decodeEscapedUnicode` en el frontend.
2. Sin embargo, al cargar las plantillas existentes (`load_templates`) en la inicialización o al refrescar el editor, los datos del estado `templates` se asignan directamente con los valores del backend sin ser pasados por el decodificador de frontend:
   ```typescript
   // En TemplateEditorWindow.tsx
   const [tmpl, lc, ns, ps] = await Promise.all([
     invoke("load_templates"), // Carga los caracteres sin normalizar en el frontend
     ...
   ]);
   setTemplates(tmpl); // Se almacena la plantilla directamente
   ```
   Si los caracteres de la plantilla contienen escapes heredados, el frontend los renderiza literalmente como texto `"\\uXXXX"`.

> [!IMPORTANT]
> Si los datos no se limpian y decodifican uniformemente en todos los puntos de entrada del frontend, cualquier secuencia de escape leída desde archivos antiguos se mostrará textualmente.

### Causa B: Incompatibilidad de Fuentes y Falta de Fallbacks CJK en Linux

El sistema de estilos utiliza principalmente la fuente de sistema y la tipografía monoespaciada para desarrolladores **JetBrains Mono** (`@fontsource/jetbrains-mono`).
- Las fuentes monoespaciadas estándar de programación **no incluyen los glifos de alfabetos CJK** (Chino, Japonés, Coreano).
- En el código de `TemplateEditorWindow.tsx`, los botones de los caracteres de la paleta utilizan la clase de Tailwind `font-sans`:
  ```tsx
  className="w-8 h-8 rounded flex items-center justify-center text-[13px] font-sans ..."
  ```
- Si la pila de fuentes `font-sans` no tiene fallbacks explícitos definidos en el archivo CSS del proyecto, o si el sistema operativo Linux donde se ejecuta la aplicación no dispone de los paquetes de fuentes CJK instalados, el navegador del WebView de Tauri no podrá renderizar el carácter. En su lugar, mostrará bloques vacíos conocidos como **tofus** o rectángulos con el código hexadecimal adentro.

---

## 3. Soluciones Propuestas

Para corregir definitivamente esta anomalía, se deben aplicar las siguientes soluciones conjuntas:

### Solución 1: Forzar la decodificación de plantillas en el Frontend

Se debe asegurar que, al cargar las plantillas de la base de datos al inicializar la pantalla, cada carácter sea procesado por la función `decodeEscapedUnicode`. 

Modificar la inicialización en `TemplateEditorWindow.tsx` para normalizar las plantillas de la siguiente manera:

```typescript
// 1. Crear una función auxiliar para normalizar los caracteres de la plantilla en el frontend
const normalizeTemplates = (rawTemplates: Record<string, TemplateData>): Record<string, TemplateData> => {
  return Object.fromEntries(
    Object.entries(rawTemplates).map(([name, data]) => [
      name,
      {
        ...data,
        chars: data.chars.map(decodeEscapedUnicode)
      }
    ])
  );
};

// 2. Aplicar la función al cargar los datos en useEffect y reloadTemplates
const [tmpl, lc, ns, ps]: any = await Promise.all([
  invoke("load_templates"),
  invoke("get_language_characters"),
  invoke("get_language_numbers_signs"),
  invoke("get_template_presets"),
]);
setTemplates(normalizeTemplates(tmpl));
```

---

### Solución 2: Usar la pila de fuentes correcta con Fallbacks CJK en la Interfaz

En `src/index.css`, se definió una excelente lista de fallbacks tipográficos CJK en `--font-mono`, pero no se asignó en `--font-sans`. Se proponen dos vías complementarias:

1. **Modificar el estilo de la paleta**: Cambiar el estilo de los botones del editor de plantillas en `TemplateEditorWindow.tsx` para que utilicen la clase `font-mono` (que incluye la cadena de fallbacks) en lugar de `font-sans`.
   ```diff
   - className="w-8 h-8 rounded flex items-center justify-center text-[13px] font-sans font-bold border"
   + className="w-8 h-8 rounded flex items-center justify-center text-[13px] font-mono font-bold border"
   ```

2. **Extender el tema en `src/index.css`**: Definir explícitamente los fallbacks tipográficos para la familia sans-serif del proyecto dentro de la directiva `@theme`:
   ```css
   @theme {
     --font-sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans CJK SC", "Noto Sans CJK KR", "Noto Sans CJK JP", sans-serif;
   }
   ```

---

### Solución 3: Instalación de dependencias de fuentes CJK en el Sistema Operativo (Linux)

Si el sistema operativo Linux carece de tipografías asiáticas instaladas, el sistema no tendrá glifos para pintar los caracteres decodificados. Para solucionarlo en la máquina del usuario, se debe ejecutar el siguiente comando en la terminal del sistema:

```bash
sudo apt update
sudo apt install fonts-noto-cjk fonts-nanum fonts-ipafont-gothic fonts-wqy-microhei
```

*Esto instalará las fuentes Noto de Google para CJK, las fuentes coreanas Nanum, las fuentes japonesas IPA y las fuentes chinas WenQuanYi Micro Hei.*
