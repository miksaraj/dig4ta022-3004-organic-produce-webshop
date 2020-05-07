<template>
	<div>
		<options-row :type="type" />
		<card-deck v-if="view === 'cards'" :items="items" :type="type" />
		<accordion-list v-if="view === 'list'" :items="items" />
	</div>
</template>

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
