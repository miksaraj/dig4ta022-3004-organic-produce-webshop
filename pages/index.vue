<template>
	<div>
		<b-card
			overlay
			title="Psyka 1"
			img-src="/img/aloitus.jpg"
			img-alt="Aloitus"
			style="width: 100%;"
			class="hero-card"
		>
			<b-card-text>
				Tähän vois kirjoittaa jotain, mitä ny sit ikinästäkään.
			</b-card-text>
			<template v-slot:footer>
				<options-row :type="type" />
			</template>
		</b-card>
		<card-deck v-if="view === 'cards'" :items="items" :type="type" />
		<accordion-list v-if="view === 'list'" :items="items" />
	</div>
</template>

<style scoped>
/* muokka näitä ja tämän cardin propseja, jos haluat erilaisen/paremman tästä */
.hero-card {
	margin-bottom: 2rem;
	background-color: var(--color-secondary);
	/* color: #ffffff; */
}

.hero-card .card-footer .row {
	margin-bottom: unset !important;
}

.hero-card .card-title {
	margin-top: 31rem;
}
</style>

<script>
import CardDeck from '~/components/CardDeck.vue'
import OptionsRow from '~/components/OptionsRow.vue'
import AccordionList from '~/components/AccordionList.vue'
export default {
	components: {
		CardDeck,
		OptionsRow,
		AccordionList
	},
	data() {
		return {
			type: 'chapters'
		}
	},
	computed: {
		items() {
			return this.$store.state.chapters.list
		},
		view() {
			return this.$store.state.settings.chaptersView
		}
	}
}
</script>
