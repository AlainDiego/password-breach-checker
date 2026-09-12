import hashlib
import requests
import threading
import time
import os
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import pandas as pd
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

CORES = {
    "Crítico": "FFC7CE",
    "Alto": "FFEB9C",
    "Médio": "FFF2CC",
    "Seguro": "C6EFCE",
}


# ----------------- Lógica de consulta e análise -----------------

def consultar_hibp(senha: str) -> int:
    """Verifica quantas vezes uma senha apareceu em vazamentos conhecidos,
    usando o modelo de k-anonimato da API do Have I Been Pwned."""
    sha1_hash = hashlib.sha1(senha.encode('utf-8')).hexdigest().upper()
    prefixo, sufixo = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefixo}"

    try:
        resposta = requests.get(url, timeout=10)
        resposta.raise_for_status()
    except requests.RequestException:
        return -1

    for linha in resposta.text.splitlines():
        sufixo_retornado, contagem = linha.split(':')
        if sufixo_retornado == sufixo:
            return int(contagem)
    return 0


def classificar_risco(ocorrencias: int, senha: str) -> str:
    if ocorrencias == -1:
        return "Erro na consulta"
    if ocorrencias > 100000:
        return "Crítico"
    if ocorrencias > 0:
        return "Alto"
    if len(senha) < 10:
        return "Médio"
    return "Seguro"


def analisar_padroes(senha: str) -> str:
    observacoes = []
    if senha.isdigit():
        observacoes.append("Somente números")
    if len(set(senha)) <= 2:
        observacoes.append("Muita repetição de caracteres")
    if len(senha) < 8:
        observacoes.append("Muito curta")
    return "; ".join(observacoes) if observacoes else "Sem padrões óbvios de fraqueza"


def recomendacao(risco: str) -> str:
    mapa = {
        "Crítico": "Trocar imediatamente",
        "Alto": "Trocar em breve",
        "Médio": "Fortalecer (aumentar tamanho/complexidade)",
        "Seguro": "Nenhuma ação necessária",
        "Erro na consulta": "Verificar manualmente",
    }
    return mapa.get(risco, "")


def pontuar_seguranca(senha: str, ocorrencias: int) -> int:
    """Calcula uma nota de 1 a 10 para a força da senha,
    considerando tamanho, variedade de caracteres e vazamentos."""
    pontos = 0

    # Tamanho
    if len(senha) >= 12:
        pontos += 4
    elif len(senha) >= 10:
        pontos += 3
    elif len(senha) >= 8:
        pontos += 2
    elif len(senha) >= 6:
        pontos += 1

    # Variedade de caracteres
    if any(c.islower() for c in senha):
        pontos += 1
    if any(c.isupper() for c in senha):
        pontos += 1
    if any(c.isdigit() for c in senha):
        pontos += 1
    if any(not c.isalnum() for c in senha):
        pontos += 2

    # Repetição excessiva reduz pontos
    if len(set(senha)) <= max(1, len(senha) // 3):
        pontos -= 2

    pontos = max(1, min(10, pontos))

    # Vazamento derruba a nota drasticamente, independente do resto
    if ocorrencias == -1:
        return pontos  # não sabemos se vazou, mantém nota baseada na força
    if ocorrencias > 100000:
        pontos = 1
    elif ocorrencias > 1000:
        pontos = min(pontos, 2)
    elif ocorrencias > 0:
        pontos = min(pontos, 3)

    return pontos


def gerar_dicas(senha: str, ocorrencias: int) -> list:
    """Retorna uma lista de dicas específicas do que falta na senha."""
    dicas = []

    if ocorrencias > 0:
        dicas.append("Essa senha já vazou — troque por uma nova, nunca a reutilize.")
    if len(senha) < 12:
        dicas.append("Aumente para pelo menos 12 caracteres.")
    if not any(c.isupper() for c in senha):
        dicas.append("Adicione letras maiúsculas.")
    if not any(c.islower() for c in senha):
        dicas.append("Adicione letras minúsculas.")
    if not any(c.isdigit() for c in senha):
        dicas.append("Adicione números.")
    if not any(not c.isalnum() for c in senha):
        dicas.append("Adicione símbolos (ex: ! @ # $ %).")
    if len(set(senha)) <= max(1, len(senha) // 3):
        dicas.append("Evite repetir os mesmos caracteres várias vezes.")
    if senha.isdigit() or senha.isalpha():
        dicas.append("Misture tipos de caracteres em vez de usar só um tipo.")

    if not dicas:
        dicas.append("Senha sólida — nenhuma melhoria óbvia necessária.")

    return dicas


# ----------------- Interface -----------------

class App(tk.Tk):
    COR_FUNDO = "#14181F"
    COR_PAINEL = "#1C222C"
    COR_TEXTO = "#E9ECEF"
    COR_ACENTO = "#E3A857"

    def __init__(self):
        super().__init__()
        self.title("Verificador de Senhas Vazadas")
        self.geometry("480x560")
        self.configure(bg=self.COR_FUNDO)
        self.resizable(False, False)

        self._id_agendado = None  # controla o debounce da digitação
        self.senha_visivel = False

        estilo = ttk.Style(self)
        estilo.theme_use("clam")
        estilo.configure("TButton", padding=8, font=("Segoe UI", 10, "bold"))
        estilo.configure("TProgressbar", troughcolor=self.COR_PAINEL,
                          background=self.COR_ACENTO)

        titulo = tk.Label(
            self, text="Verificador de Senhas Vazadas",
            bg=self.COR_FUNDO, fg=self.COR_TEXTO, font=("Georgia", 15, "bold")
        )
        titulo.pack(pady=(20, 5))

        subtitulo = tk.Label(
            self, text="Digite uma senha para checar automaticamente",
            bg=self.COR_FUNDO, fg="#9AA4B2", font=("Segoe UI", 9)
        )
        subtitulo.pack(pady=(0, 10))

        # --- Campo de senha com botão de mostrar/ocultar ---
        frame_senha = tk.Frame(self, bg=self.COR_FUNDO)
        frame_senha.pack(pady=5)

        self.var_senha = tk.StringVar()
        self.var_senha.trace_add("write", self._agendar_verificacao)

        self.entrada = tk.Entry(frame_senha, textvariable=self.var_senha, show="*",
                                 width=27, font=("Consolas", 12))
        self.entrada.pack(side="left")

        self.botao_olho = tk.Button(
            frame_senha, text="Mostrar", width=8, font=("Segoe UI", 9),
            bg=self.COR_PAINEL, fg=self.COR_TEXTO, relief="flat",
            activebackground=self.COR_PAINEL, activeforeground=self.COR_ACENTO,
            command=self._alternar_visibilidade
        )
        self.botao_olho.pack(side="left", padx=(6, 0))

        self.resultado = tk.Label(
            self, text="", bg=self.COR_FUNDO, fg=self.COR_ACENTO,
            font=("Consolas", 10), wraplength=420, justify="left"
        )
        self.resultado.pack(pady=10, padx=20)

        separador = ttk.Separator(self, orient="horizontal")
        separador.pack(fill="x", padx=20, pady=15)

        subtitulo2 = tk.Label(
            self, text="Ou processe uma planilha inteira",
            bg=self.COR_FUNDO, fg="#9AA4B2", font=("Segoe UI", 9)
        )
        subtitulo2.pack()

        self.botao_planilha = ttk.Button(
            self, text="Selecionar Excel", command=self.selecionar_planilha
        )
        self.botao_planilha.pack(pady=10)

        self.barra_progresso = ttk.Progressbar(
            self, orient="horizontal", length=380, mode="determinate"
        )
        self.barra_progresso.pack(pady=5)

        self.status_planilha = tk.Label(
            self, text="", bg=self.COR_FUNDO, fg="#9AA4B2", font=("Segoe UI", 9)
        )
        self.status_planilha.pack()

    # ----- Mostrar/ocultar senha -----

    def _alternar_visibilidade(self):
        self.senha_visivel = not self.senha_visivel
        if self.senha_visivel:
            self.entrada.config(show="")
            self.botao_olho.config(text="Ocultar")
        else:
            self.entrada.config(show="*")
            self.botao_olho.config(text="Mostrar")

    # ----- Verificação individual com debounce -----

    def _agendar_verificacao(self, *args):
        if self._id_agendado is not None:
            self.after_cancel(self._id_agendado)
        senha = self.var_senha.get()
        if not senha:
            self.resultado.config(text="")
            return
        self.resultado.config(text="Consultando...")
        self._id_agendado = self.after(600, self._verificar_agora, senha)

    def _verificar_agora(self, senha):
        threading.Thread(target=self._verificar_thread, args=(senha,), daemon=True).start()

    def _verificar_thread(self, senha):
        ocorrencias = consultar_hibp(senha)
        self.after(0, self._mostrar_resultado, senha, ocorrencias)

    def _mostrar_resultado(self, senha, ocorrencias):
        # Se o usuário já apagou/mudou o campo enquanto a consulta rodava, ignora
        if senha != self.var_senha.get():
            return

        if ocorrencias == -1:
            self.resultado.config(text="Não foi possível completar a verificação.")
            return

        nota = pontuar_seguranca(senha, ocorrencias)
        dicas = gerar_dicas(senha, ocorrencias)

        if ocorrencias > 0:
            cabecalho = f"Essa senha já apareceu {ocorrencias:,} vezes em vazamentos conhecidos."
        else:
            cabecalho = "Boa notícia: essa senha não apareceu em vazamentos conhecidos."

        linhas_dicas = "\n".join(f"• {dica}" for dica in dicas)
        texto = (
            f"{cabecalho}\n"
            f"Nível de segurança: {nota} de 10\n\n"
            f"Como melhorar:\n{linhas_dicas}"
        )
        self.resultado.config(text=texto)

    # ----- Processamento de planilha -----

    def selecionar_planilha(self):
        # Usa o Desktop como ponto de partida: existe em qualquer máquina
        # Windows e evita depender de uma pasta de projeto específica
        # (algumas pastas sincronizadas com nuvem, como o OneDrive, podem
        # se comportar de forma inconsistente com caminhos aninhados).
        pasta_inicial = os.path.join(os.path.expanduser("~"), "Desktop")
        if not os.path.isdir(pasta_inicial):
            pasta_inicial = os.path.expanduser("~")

        caminho_entrada = filedialog.askopenfilename(
            title="Selecione a planilha com as senhas",
            initialdir=pasta_inicial,
            filetypes=[("Arquivos Excel", "*.xlsx")]
        )
        if not caminho_entrada:
            return

        caminho_saida = filedialog.asksaveasfilename(
            title="Salvar relatório como",
            initialdir=pasta_inicial,
            defaultextension=".xlsx",
            initialfile="relatorio_seguranca.xlsx",
            filetypes=[("Arquivos Excel", "*.xlsx")]
        )
        if not caminho_saida:
            return

        self.botao_planilha.config(state="disabled")
        self.status_planilha.config(text="Processando...")
        self.barra_progresso["value"] = 0

        threading.Thread(
            target=self._processar_planilha_thread,
            args=(caminho_entrada, caminho_saida),
            daemon=True
        ).start()

    def _processar_planilha_thread(self, caminho_entrada, caminho_saida):
        try:
            # Lê a planilha de entrada: primeira coluna, sem cabeçalho
            df_entrada = pd.read_excel(caminho_entrada, header=None, usecols=[0])
            senhas = df_entrada[0].dropna().astype(str).str.strip().tolist()
            senhas = [s for s in senhas if s]

            total = len(senhas)
            if total == 0:
                self.after(0, self._erro_planilha, "A planilha não tem senhas na coluna A.")
                return

            linhas = []
            senhas_vistas = {}
            contagem_riscos = {"Crítico": 0, "Alto": 0, "Médio": 0, "Seguro": 0, "Erro na consulta": 0}
            duplicadas = 0

            for i, senha in enumerate(senhas, start=1):
                ocorrencias = consultar_hibp(senha)
                risco = classificar_risco(ocorrencias, senha)
                nota = pontuar_seguranca(senha, ocorrencias)
                observacoes = analisar_padroes(senha)
                recomenda = recomendacao(risco)
                agora = datetime.now().strftime("%Y-%m-%d %H:%M")

                if senha in senhas_vistas:
                    duplicadas += 1
                    observacoes += "; Senha duplicada na planilha"
                senhas_vistas[senha] = senhas_vistas.get(senha, 0) + 1

                linhas.append({
                    "Senha": senha,
                    "Ocorrências em vazamentos": ocorrencias if ocorrencias != -1 else "Erro",
                    "Nível de risco": risco,
                    "Nota de segurança (1-10)": nota,
                    "Observações": observacoes,
                    "Recomendação": recomenda,
                    "Verificado em": agora,
                })

                contagem_riscos[risco] = contagem_riscos.get(risco, 0) + 1

                progresso = int((i / total) * 100)
                self.after(0, self._atualizar_progresso, progresso, i, total)

                time.sleep(0.2)

            df_detalhes = pd.DataFrame(linhas)

            resumo_linhas = [("Total de senhas verificadas", total)]
            for risco, qtd in contagem_riscos.items():
                percentual = f"{(qtd / total * 100):.1f}%" if total else "0%"
                resumo_linhas.append((risco, f"{qtd} ({percentual})"))
            resumo_linhas.append(("Senhas duplicadas na planilha", duplicadas))
            resumo_linhas.append(("Data do relatório", datetime.now().strftime("%Y-%m-%d %H:%M")))
            df_resumo = pd.DataFrame(resumo_linhas, columns=["Métrica", "Valor"])

            # Pandas monta as tabelas; openpyxl (por baixo do writer) cuida do visual
            with pd.ExcelWriter(caminho_saida, engine="openpyxl") as writer:
                df_detalhes.to_excel(writer, sheet_name="Detalhes", index=False)
                df_resumo.to_excel(writer, sheet_name="Resumo", index=False)

                aba_detalhes = writer.sheets["Detalhes"]
                aba_resumo = writer.sheets["Resumo"]

                # Cabeçalho da aba Detalhes
                for celula in aba_detalhes[1]:
                    celula.font = Font(bold=True, color="FFFFFF")
                    celula.fill = PatternFill(start_color="2C3440", end_color="2C3440", fill_type="solid")
                    celula.alignment = Alignment(horizontal="center")
                aba_detalhes.freeze_panes = "A2"

                # Colore cada linha conforme o nível de risco
                for indice, risco in enumerate(df_detalhes["Nível de risco"], start=2):
                    cor = CORES.get(risco)
                    if cor:
                        preenchimento = PatternFill(start_color=cor, end_color=cor, fill_type="solid")
                        for celula in aba_detalhes[indice]:
                            celula.fill = preenchimento

                for coluna in aba_detalhes.columns:
                    maior = max(len(str(c.value)) for c in coluna)
                    letra = get_column_letter(coluna[0].column)
                    aba_detalhes.column_dimensions[letra].width = min(maior + 2, 50)

                # Cabeçalho da aba Resumo
                for celula in aba_resumo[1]:
                    celula.font = Font(bold=True)
                aba_resumo.column_dimensions["A"].width = 32
                aba_resumo.column_dimensions["B"].width = 20

            self.after(0, self._concluir_planilha, caminho_saida)

        except Exception as erro:
            self.after(0, self._erro_planilha, str(erro))

    def _atualizar_progresso(self, progresso, atual, total):
        self.barra_progresso["value"] = progresso
        self.status_planilha.config(text=f"Processando {atual} de {total}...")

    def _concluir_planilha(self, caminho_saida):
        self.botao_planilha.config(state="normal")
        self.status_planilha.config(text="Relatório gerado com sucesso!")
        messagebox.showinfo("Concluído", f"Relatório salvo em:\n{caminho_saida}")

    def _erro_planilha(self, mensagem):
        self.botao_planilha.config(state="normal")
        self.status_planilha.config(text="Erro no processamento.")
        messagebox.showerror("Erro", mensagem)


if __name__ == "__main__":
    app = App()
    app.mainloop()
